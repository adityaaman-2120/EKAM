"""Tests for :mod:`ulpf.core.runtime` — the wired-together process."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.runtime import Runtime
from ulpf.sinks.raw_store import RawStore


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
        pipeline=PipelineSettings(worker_count=1),
    )


async def test_udp_datagram_ends_up_in_the_bronze_store(tmp_path: Path) -> None:
    """`ulpf run` wiring: a syslog UDP datagram becomes one bronze record."""
    settings = _settings(tmp_path)
    runtime = Runtime(settings)
    await runtime.start()
    try:
        assert runtime.udp_port > 0
        assert runtime.tcp_port > 0
        assert runtime.tls_port is None  # no cert configured

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", runtime.udp_port)
        )
        transport.sendto(b"test\n")
        transport.close()
        await asyncio.sleep(0.15)  # let datagram_received -> pipeline.submit run
    finally:
        await runtime.stop()  # stops UDP (drains dispatch), then flushes bronze

    events = list(RawStore(settings).iter_all())
    assert len(events) == 1
    assert events[0].raw == b"test\n"
    assert events[0].transport == "udp"
    assert events[0].source_id == "syslog-udp"

    partitions = list((tmp_path / "bronze").rglob("events.ndjson.gz"))
    assert len(partitions) == 1


async def test_start_then_stop_is_clean_with_no_traffic(tmp_path: Path) -> None:
    runtime = Runtime(_settings(tmp_path))
    await runtime.start()
    await runtime.stop()
    # a second stop is a no-op, not an error
    await runtime.pipeline.stop()
