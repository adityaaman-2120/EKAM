"""Asyncio TCP syslog listener with RFC 6587 framing detection.

RFC 6587 defines **two mutually incompatible** ways to delimit syslog messages
on a TCP stream, and a robust reader must cope with both — even interleaved on
one connection:

1. **Octet-counting** — ``MSGLEN SP MSG``: ASCII digits, one space, then exactly
   ``MSGLEN`` octets of message. Binary-safe; the message may itself contain
   newlines or start with digits.
2. **Non-transparent-framing** — ``MSG LF`` (occasionally ``MSG CR LF``):
   messages are separated by a newline and must not contain one.

Detection, per message, on the head of the buffer:

* If it begins with ASCII digits **immediately followed by a space**, and those
  digits parse as an integer, it is octet-counting — read exactly that many
  bytes and do not stop at a newline inside them.
* Otherwise read up to (and drop) the next ``LF``, trimming a trailing ``CR``.

Digits that are *not* followed by a space (``12345-...``, ``999999\\n``) are
ordinary message content and fall through to newline framing — a message body
starting with a digit is never mistaken for a length prefix. The one
irreducible ambiguity RFC 6587 itself calls out — a newline-framed message that
literally begins ``<digits><space>`` — is resolved in favour of octet-counting,
as the spec's own text does.

Partial reads are held: if the full declared body (octet-counting) or a
terminating newline (non-transparent) has not arrived, nothing is emitted and
more data is awaited. Bytes are never decoded; each frame becomes one
:class:`~ulpf.core.models.RawEvent` via
:func:`~ulpf.integrity.hashing.make_raw_event`.

:class:`FramedListenerBase` holds the connection-handling logic shared with the
TLS listener (:mod:`ulpf.ingest.syslog_tls`); only the ``start`` step differs.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import ClassVar

from ulpf.core.errors import IngestError
from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED
from ulpf.core.models import RawEvent, Transport
from ulpf.integrity.hashing import make_raw_event

_log = logging.getLogger(__name__)

OnEvent = Callable[[RawEvent], Awaitable[None]]

_READ_SIZE = 65_536
_DEFAULT_MAX_FRAME = 1 << 20  # 1 MiB: cap a hostile/garbled octet count
_SPACE = 0x20
_DIGITS = frozenset(range(0x30, 0x3A))  # b"0" .. b"9"


def _read_octet_body(
    buf: bytearray, space_index: int, max_frame_bytes: int
) -> tuple[bytes | None, bytearray]:
    """Extract an octet-counted body once ``buf[:space_index]`` is its length."""
    length = int(buf[:space_index])
    if length > max_frame_bytes:
        raise IngestError(
            "octet-counted frame exceeds max_frame_bytes",
            detail={"declared": length, "limit": max_frame_bytes},
        )
    start = space_index + 1
    if len(buf) - start < length:
        return None, buf  # body not fully arrived yet
    return bytes(buf[start : start + length]), bytearray(buf[start + length :])


def _try_newline(buf: bytearray) -> tuple[bytes | None, bytearray]:
    """Extract one non-transparent (newline-terminated) frame, if present."""
    idx = buf.find(b"\n")
    if idx == -1:
        return None, buf
    line = buf[:idx]
    if line.endswith(b"\r"):
        line = line[:-1]
    return bytes(line), bytearray(buf[idx + 1 :])


def _next_frame(buf: bytearray, max_frame_bytes: int) -> tuple[bytes | None, bytearray]:
    """Return ``(frame, remainder)`` for the head of ``buf``.

    ``frame`` is ``None`` when more bytes are needed; ``buf`` is returned
    unchanged in that case.
    """
    if not buf:
        return None, buf
    if buf[0] in _DIGITS:
        i = 0
        while i < len(buf) and buf[i] in _DIGITS:
            i += 1
        if i == len(buf):
            return None, buf  # still buffering a possible length prefix
        if buf[i] == _SPACE:
            return _read_octet_body(buf, i, max_frame_bytes)
        # digits followed by a non-space byte: this is message content.
    return _try_newline(buf)


def _final_frame(buf: bytearray) -> bytes | None:
    """At EOF, salvage a trailing non-transparent message with no final newline.

    An incomplete octet-counted frame (declared length unmet) is discarded.
    """
    if not buf:
        return None
    if buf[0] in _DIGITS:
        i = 0
        while i < len(buf) and buf[i] in _DIGITS:
            i += 1
        if i == len(buf) or buf[i] == _SPACE:
            return None  # unterminated length prefix / short octet body
    tail = bytes(buf).rstrip(b"\r\n")
    return tail or None


async def read_frames(
    reader: asyncio.StreamReader, *, max_frame_bytes: int = _DEFAULT_MAX_FRAME
) -> AsyncIterator[bytes]:
    """Yield one message per RFC 6587 frame from ``reader`` until EOF.

    Auto-detects octet-counting vs. non-transparent framing per message and
    buffers partial reads. Zero-length frames are skipped. Raises
    :class:`IngestError` if an octet count exceeds ``max_frame_bytes``.
    """
    buf = bytearray()
    while True:
        frame, buf = _next_frame(buf, max_frame_bytes)
        if frame is not None:
            if frame:
                yield frame
            continue
        chunk = await reader.read(_READ_SIZE)
        if not chunk:
            break
        buf.extend(chunk)
    tail = _final_frame(buf)
    if tail:
        yield tail


class FramedListenerBase:
    """Shared machinery for stream syslog listeners (TCP and TLS).

    Subclasses set :attr:`transport` and implement :meth:`start`; everything
    else — per-connection framing, metrics, dispatch, shutdown — is here.
    No global state: the server, callback, and open connections are instance
    attributes.
    """

    transport: ClassVar[Transport]

    def __init__(self, source_id: str, *, max_frame_bytes: int = _DEFAULT_MAX_FRAME) -> None:
        """Initialise shared listener state."""
        self._source_id = source_id
        self._max_frame_bytes = max_frame_bytes
        self._server: asyncio.Server | None = None
        self._on_event: OnEvent | None = None
        self._conns: set[asyncio.Task[None]] = set()

    async def start(self, host: str, port: int, on_event: OnEvent) -> None:  # pragma: no cover
        """Bind and begin accepting connections. Implemented by subclasses."""
        raise NotImplementedError

    async def stop(self) -> None:
        """Stop accepting, then wait for open connections to drain."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)

    @property
    def sockname(self) -> tuple[str | int, ...]:
        """The bound ``(host, port, ...)`` tuple. Raises if not started."""
        if self._server is None:
            raise RuntimeError("listener not started")
        return self._server.sockets[0].getsockname()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Read RFC 6587 frames from one connection until it closes or mis-frames."""
        peername = writer.get_extra_info("peername")
        peer = str(peername[0]) if peername else None
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
            task.add_done_callback(self._conns.discard)
        try:
            async for frame in read_frames(reader, max_frame_bytes=self._max_frame_bytes):
                EVENTS_RECEIVED.labels(transport=self.transport).inc()
                BYTES_RECEIVED.labels(transport=self.transport).inc(len(frame))
                event = make_raw_event(
                    frame, source_id=self._source_id, transport=self.transport, peer=peer
                )
                await self._dispatch(event)
        except IngestError as exc:
            _log.warning(
                "%s syslog framing error; closing", self.transport,
                extra={"peer": peer, "err": str(exc)},
            )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _dispatch(self, event: RawEvent) -> None:
        """Await the user callback for one event, isolating its failures."""
        assert self._on_event is not None
        try:
            await self._on_event(event)
        except Exception:  # noqa: BLE001 - a bad callback must not kill the connection
            _log.exception("%s syslog on_event failed", self.transport,
                           extra={"event_uid": event.event_uid})


class SyslogTcpListener(FramedListenerBase):
    """Plaintext TCP syslog server that emits one :class:`RawEvent` per frame."""

    transport = "tcp"

    def __init__(
        self, source_id: str = "syslog-tcp", *, max_frame_bytes: int = _DEFAULT_MAX_FRAME
    ) -> None:
        """Create a listener tagging events with ``source_id``."""
        super().__init__(source_id, max_frame_bytes=max_frame_bytes)

    async def start(self, host: str, port: int, on_event: OnEvent) -> None:
        """Bind ``host:port`` (``port=0`` for ephemeral) and frame each connection."""
        self._on_event = on_event
        self._server = await asyncio.start_server(self._handle_client, host, port)
