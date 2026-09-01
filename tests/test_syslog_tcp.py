"""Tests for :mod:`ulpf.ingest.syslog_tcp` — RFC 6587 framing."""

from __future__ import annotations

import asyncio
import hashlib

import pytest

from ulpf.core.models import RawEvent
from ulpf.ingest.syslog_tcp import SyslogTcpListener, read_frames


def _reader(*chunks: bytes) -> asyncio.StreamReader:
    """A StreamReader pre-fed with ``chunks`` and then EOF."""
    reader = asyncio.StreamReader()
    for chunk in chunks:
        reader.feed_data(chunk)
    reader.feed_eof()
    return reader


async def _frames(*chunks: bytes) -> list[bytes]:
    return [frame async for frame in read_frames(_reader(*chunks))]


def _octet(msg: bytes) -> bytes:
    return f"{len(msg)} ".encode() + msg


# --------------------------------------------------------------------------
# read_frames


async def test_pure_octet_counted_stream() -> None:
    m1 = b"<34>1 2003-10-11T22:14:15.003Z host app - - - hello world"
    m2 = b"<13>1 2003-10-11T22:14:16Z host app - - - second message!"
    assert await _frames(_octet(m1) + _octet(m2)) == [m1, m2]


async def test_octet_counted_body_may_contain_a_newline() -> None:
    m = b"<34>1 host app - - - line one\nstill same message"
    assert await _frames(_octet(m)) == [m]


async def test_pure_newline_stream_lf_and_crlf() -> None:
    assert await _frames(b"<34>msg one\n<13>msg two\n<7>msg three\n") == [
        b"<34>msg one",
        b"<13>msg two",
        b"<7>msg three",
    ]
    assert await _frames(b"<1>a\r\n<2>b\r\n") == [b"<1>a", b"<2>b"]


async def test_newline_stream_trailing_message_without_newline_at_eof() -> None:
    assert await _frames(b"<1>complete\n<2>no trailing newline") == [
        b"<1>complete",
        b"<2>no trailing newline",
    ]


async def test_mixed_stream_octet_then_newline_then_octet() -> None:
    a = b"<1>AAAA octet framed"
    b = b"<2>BBBB newline framed"
    c = b"<3>CCCC octet framed again"
    stream = _octet(a) + b + b"\n" + _octet(c)
    assert await _frames(stream) == [a, b, c]


async def test_message_split_across_two_reads_octet() -> None:
    msg = b"<34>1 2003-10-11T22:14:15Z host app - - - split across two tcp reads"
    framed = _octet(msg)
    for cut in (1, 3, len(framed) // 2, len(framed) - 1):
        assert await _frames(framed[:cut], framed[cut:]) == [msg], f"cut={cut}"


async def test_message_split_across_two_reads_newline() -> None:
    assert await _frames(b"<1>partial ", b"line one\n<2>line two\n") == [
        b"<1>partial line one",
        b"<2>line two",
    ]


async def test_body_starting_with_digit_is_not_read_as_length_prefix() -> None:
    # digits followed by a non-space -> ordinary newline-framed content
    assert await _frames(b"12345-not-a-length prefix here\n") == [
        b"12345-not-a-length prefix here"
    ]
    # a message that is only digits + newline
    assert await _frames(b"999999\n") == [b"999999"]
    # octet-counted frame whose body starts with digits
    body = b"2023-10-11T22:14:15Z 42 answers, 100 questions, 7 spare"
    assert await _frames(_octet(body)) == [body]
    # digit run split across reads, then revealed as non-length content
    assert await _frames(b"123", b"456-tail\n") == [b"123456-tail"]


async def test_incomplete_octet_frame_at_eof_is_dropped() -> None:
    # declares 50 bytes, only 5 present before EOF
    assert await _frames(b"50 short") == []


# --------------------------------------------------------------------------
# SyslogTcpListener


async def test_listener_end_to_end_mixed_framing() -> None:
    got: list[RawEvent] = []
    done = asyncio.Event()

    async def on_event(event: RawEvent) -> None:
        got.append(event)
        if len(got) == 3:
            done.set()

    listener = SyslogTcpListener(source_id="test-tcp")
    await listener.start("127.0.0.1", 0, on_event)
    host, port = listener.sockname[0], listener.sockname[1]

    reader, writer = await asyncio.open_connection(host, port)
    o1 = b"<1>octet one"
    n2 = b"<2>newline two"
    o3 = b"<3>octet three"
    try:
        writer.write(_octet(o1) + n2 + b"\n" + _octet(o3))
        await writer.drain()
        await asyncio.wait_for(done.wait(), timeout=2.0)
    finally:
        writer.close()
        await writer.wait_closed()
        await listener.stop()

    assert [e.raw for e in got] == [o1, n2, o3]
    for event, raw in zip(got, [o1, n2, o3], strict=True):
        assert event.raw_hash == hashlib.sha256(raw).hexdigest()
        assert event.raw_len == len(raw)
        assert event.transport == "tcp"
        assert event.peer == "127.0.0.1"
        assert event.source_id == "test-tcp"


async def test_sockname_raises_before_start() -> None:
    listener = SyslogTcpListener()
    with pytest.raises(RuntimeError):
        _ = listener.sockname
