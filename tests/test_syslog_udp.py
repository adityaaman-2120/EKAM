"""Tests for :mod:`ulpf.ingest.syslog_udp`."""

from __future__ import annotations

import asyncio
import hashlib

from ulpf.core.metrics import snapshot
from ulpf.core.models import RawEvent
from ulpf.ingest.syslog_udp import SyslogUdpListener

_PAYLOADS = [
    b"<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built outbound TCP connection 8145",
    b"\xff\xfe binary-ish syslog \x00 payload \xc3\x28",
    b"<38>Oct 11 22:14:16 gw01 sshd[1234]: Accepted password for jdoe from 203.0.113.9",
]


async def test_three_datagrams_become_three_raw_events() -> None:
    received: list[RawEvent] = []
    done = asyncio.Event()

    async def on_event(event: RawEvent) -> None:
        received.append(event)
        if len(received) == len(_PAYLOADS):
            done.set()

    ev_key = 'ulpf_events_received_total{transport="udp"}'
    by_key = 'ulpf_bytes_received_total{transport="udp"}'
    ev_before = snapshot().get(ev_key, 0.0)
    by_before = snapshot().get(by_key, 0.0)

    listener = SyslogUdpListener(source_id="test-udp")
    await listener.start("127.0.0.1", 0, on_event)
    host, port = listener.sockname[0], listener.sockname[1]

    loop = asyncio.get_running_loop()
    sender, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=(host, port)
    )
    try:
        for payload in _PAYLOADS:
            sender.sendto(payload)
        await asyncio.wait_for(done.wait(), timeout=2.0)
    finally:
        sender.close()
        await listener.stop()

    assert len(received) == 3
    assert {event.raw for event in received} == set(_PAYLOADS)

    by_raw = {event.raw: event for event in received}
    for payload in _PAYLOADS:
        event = by_raw[payload]
        assert event.raw == payload  # bytes passed through, never decoded
        assert event.raw_hash == hashlib.sha256(payload).hexdigest()
        assert event.raw_len == len(payload)
        assert event.transport == "udp"
        assert event.peer == "127.0.0.1"
        assert event.source_id == "test-udp"

    assert snapshot()[ev_key] - ev_before == 3.0
    assert snapshot()[by_key] - by_before == float(sum(len(p) for p in _PAYLOADS))


async def test_sockname_raises_before_start() -> None:
    listener = SyslogUdpListener()
    try:
        listener.sockname
    except RuntimeError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError before start()")
