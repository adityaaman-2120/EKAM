"""Phase-1 end-to-end integration test.

Drives the real :class:`~ulpf.core.runtime.Runtime` — pipeline + UDP syslog
listener on an ephemeral port — with 1000 synthetic datagrams and proves the
lossless raw round-trip that requirement (a) demands.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from pathlib import Path

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.runtime import Runtime
from ulpf.integrity.hashing import sha256_hex
from ulpf.sinks.raw_store import RawStore

_N = 1000

_EV_KEY = 'ulpf_events_received_total{transport="udp"}'
_BY_KEY = 'ulpf_bytes_received_total{transport="udp"}'
_RAW_STORE_KEY = 'ulpf_stage_latency_seconds_count{stage="raw_store"}'
_NOOP_KEY = 'ulpf_stage_latency_seconds_count{stage="noop"}'


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ingest=IngestSettings(syslog_udp_port=0, syslog_tcp_port=0, http_port=0),
        pipeline=PipelineSettings(worker_count=4),
    )


def _payload(i: int) -> bytes:
    """A distinct synthetic RFC 3164-style syslog line for index ``i``."""
    return (
        f"<134>Oct 11 22:14:{i % 60:02d} fw01 %ASA-6-302013: "
        f"seq={i} Built outbound TCP connection {100000 + i} "
        f"for outside:203.0.113.{i % 256}/443 to inside:192.0.2.{i % 256}/{40000 + i}"
    ).encode()


async def _await_received(baseline: float, timeout: float = 30.0) -> None:
    """Block until the UDP listener has counted all ``_N`` datagrams."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while snapshot().get(_EV_KEY, 0.0) - baseline < _N and loop.time() < deadline:
        await asyncio.sleep(0.02)


async def test_1000_udp_datagrams_roundtrip_losslessly_to_bronze(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    payloads = [_payload(i) for i in range(_N)]
    total_bytes = sum(len(p) for p in payloads)

    runtime = Runtime(settings)
    await runtime.start()
    before = snapshot()

    try:
        # Headroom so a burst cannot overflow the kernel receive buffer.
        with contextlib.suppress(OSError, AttributeError):
            runtime._udp.socket.setsockopt(  # type: ignore[attr-defined]
                socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20
            )

        loop = asyncio.get_running_loop()
        sender, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", runtime.udp_port)
        )
        try:
            # Send in small chunks, yielding so the listener drains concurrently.
            for start in range(0, _N, 10):
                for payload in payloads[start : start + 10]:
                    sender.sendto(payload)
                await asyncio.sleep(0)
            await _await_received(before.get(_EV_KEY, 0.0))
        finally:
            sender.close()
    finally:
        await runtime.stop()  # drains the queue and flushes the bronze store

    after = snapshot()

    # (5) metrics counters match exactly.
    assert after.get(_EV_KEY, 0.0) - before.get(_EV_KEY, 0.0) == float(_N)
    assert after.get(_BY_KEY, 0.0) - before.get(_BY_KEY, 0.0) == float(total_bytes)
    assert after.get(_RAW_STORE_KEY, 0.0) - before.get(_RAW_STORE_KEY, 0.0) == float(_N)
    assert after.get(_NOOP_KEY, 0.0) - before.get(_NOOP_KEY, 0.0) == float(_N)
    assert after["ulpf_queue_depth"] == 0.0
    assert runtime.pipeline.dlq.stats()["total"] == 0

    # (3) all 1000 land in bronze with distinct event_uids.
    events = list(RawStore(settings).iter_all())
    assert len(events) == _N
    assert len({e.event_uid for e in events}) == _N

    # (4) requirement (a): every stored raw re-hashes to its recorded raw_hash,
    #     and the bytes are exactly what was sent — nothing lost or altered.
    for event in events:
        assert sha256_hex(event.raw) == event.raw_hash
        assert event.transport == "udp"
        assert event.source_id == "syslog-udp"
    assert {e.raw for e in events} == set(payloads)
