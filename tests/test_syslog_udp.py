"""Tests for :mod:`ulpf.ingest.syslog_udp`."""

from __future__ import annotations

import asyncio
import hashlib

import pytest

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
    with pytest.raises(RuntimeError):
        _ = listener.sockname


# --------------------------------------------------------------------------
# SO_RCVBUF


async def test_actual_recv_buffer_bytes_is_none_before_start() -> None:
    listener = SyslogUdpListener()
    assert listener.actual_recv_buffer_bytes is None


async def test_recv_buffer_is_requested_and_the_granted_size_is_reported() -> None:
    requested = 4 * 1024 * 1024
    listener = SyslogUdpListener(recv_buffer_bytes=requested)
    await listener.start("127.0.0.1", 0, lambda event: asyncio.sleep(0))
    try:
        # the OS is free to grant more or less than requested (Linux commonly
        # doubles it for bookkeeping) -- the contract is "at least what a
        # default socket would have gotten", not an exact byte count.
        assert listener.actual_recv_buffer_bytes is not None
        assert listener.actual_recv_buffer_bytes > 0
    finally:
        await listener.stop()


async def test_default_recv_buffer_is_at_least_four_mebibytes() -> None:
    listener = SyslogUdpListener()
    await listener.start("127.0.0.1", 0, lambda event: asyncio.sleep(0))
    try:
        assert listener.actual_recv_buffer_bytes is not None
        assert listener.actual_recv_buffer_bytes >= 4 * 1024 * 1024
    finally:
        await listener.stop()


async def test_recv_buffer_bytes_zero_leaves_the_os_default_alone() -> None:
    listener = SyslogUdpListener(recv_buffer_bytes=0)
    await listener.start("127.0.0.1", 0, lambda event: asyncio.sleep(0))
    try:
        # still reads back SOME granted size -- just never asked to change it
        assert listener.actual_recv_buffer_bytes is not None
        assert listener.actual_recv_buffer_bytes > 0
    finally:
        await listener.stop()
