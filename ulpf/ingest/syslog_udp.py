"""Asyncio UDP syslog listener (RFC 3164 / RFC 5426 style datagrams).

**UDP syslog is lossy by design.** The transport has no handshake, no
acknowledgements, no retransmission, and no sequence numbers. A datagram dropped
by a congested link, a full kernel receive buffer, or an overrun NIC simply
never arrives, and nothing on either side records that it existed. This listener
therefore counts exactly what it *received* — ``ulpf_events_received_total`` and
``ulpf_bytes_received_total`` — but it can never account for what it did *not*
receive. That is a property of the protocol, not a defect here; sources that
need lossless delivery must use the TCP or TLS listeners. **Benchmark and
verification runs in particular must use TCP** — a UDP sender with no pacing
can blast datagrams faster than a real device ever would, overflow the kernel
receive buffer, and silently distort every downstream measurement (sealed
count, per-source normalization rate, ...) into an artifact of the transport
rather than a fact about the pipeline. See CLAUDE.md.

The bytes of each datagram are passed through untouched: no decoding, no newline
handling, no charset guessing. Each datagram becomes exactly one
:class:`~ulpf.core.models.RawEvent` via
:func:`~ulpf.integrity.hashing.make_raw_event`, hashed before anything else sees
it.

RECEIVE BUFFER SIZE
--------------------
``recv_buffer_bytes`` (``ingest.syslog_udp_recv_buffer_bytes`` in settings,
default 4 MiB) requests a larger kernel socket receive buffer via
``SO_RCVBUF``, so a burst of datagrams has more headroom to sit queued in the
kernel while this process is busy, instead of being dropped on arrival. The OS
is free to grant less than requested (Linux silently caps/doubles per
``net.core.rmem_max``; the actual value after binding is read back and logged
at startup — see :attr:`SyslogUdpListener.actual_recv_buffer_bytes`). This
raises the burst a UDP listener can absorb; it does not, and cannot, make UDP
lossless — there is still no acknowledgement or retransmission at any buffer
size, which is the actual reason verification/benchmark runs use TCP instead.
"""

from __future__ import annotations

import asyncio
import logging
import socket as socket_module
from collections.abc import Awaitable, Callable

from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED
from ulpf.core.models import RawEvent
from ulpf.integrity.hashing import make_raw_event

_log = logging.getLogger(__name__)

OnEvent = Callable[[RawEvent], Awaitable[None]]

DEFAULT_RECV_BUFFER_BYTES = 4 * 1024 * 1024  # 4 MiB


class _SyslogDatagramProtocol(asyncio.DatagramProtocol):
    """Bridges asyncio datagram callbacks to the owning listener."""

    def __init__(self, listener: SyslogUdpListener) -> None:
        """Bind this protocol instance to its ``listener``."""
        self._listener = listener

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Record the bound transport on the listener."""
        assert isinstance(transport, asyncio.DatagramTransport)
        self._listener._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | int, ...]) -> None:
        """Hand one received datagram and its sender IP to the listener."""
        self._listener._on_datagram(data, str(addr[0]))

    def error_received(self, exc: Exception) -> None:
        """Log a transient receive error (e.g. an ICMP port-unreachable)."""
        _log.warning("udp syslog error_received", extra={"error": repr(exc)})


class SyslogUdpListener:
    """Receives syslog datagrams and emits one :class:`RawEvent` per datagram.

    No global state: the transport, callback, and in-flight tasks live on the
    instance.
    """

    def __init__(
        self,
        source_id: str = "syslog-udp",
        *,
        recv_buffer_bytes: int = DEFAULT_RECV_BUFFER_BYTES,
    ) -> None:
        """Create a listener that tags every event with ``source_id``.

        Args:
            source_id: Tag recorded on every :class:`RawEvent` this listener emits.
            recv_buffer_bytes: Requested ``SO_RCVBUF`` size, in bytes (default 4 MiB).
                The OS grants what it can; the actual size is read back and
                logged in :meth:`start`, and exposed as
                :attr:`actual_recv_buffer_bytes`. ``0`` or negative leaves the
                OS default untouched.
        """
        self._source_id = source_id
        self._recv_buffer_bytes = recv_buffer_bytes
        self._transport: asyncio.DatagramTransport | None = None
        self._on_event: OnEvent | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._actual_recv_buffer_bytes: int | None = None

    async def start(self, host: str, port: int, on_event: OnEvent) -> None:
        """Bind to ``host:port`` and deliver each datagram to ``on_event``.

        Pass ``port=0`` to bind an ephemeral port; read it back from
        :attr:`sockname`. Requests ``recv_buffer_bytes`` (see :meth:`__init__`)
        as the socket's ``SO_RCVBUF`` before binding, and logs the size the OS
        actually granted — UDP syslog is lossy under burst; see the module
        docstring.
        """
        loop = asyncio.get_running_loop()
        self._on_event = on_event
        family = socket_module.AF_INET6 if ":" in host else socket_module.AF_INET
        sock = socket_module.socket(family, socket_module.SOCK_DGRAM)
        sock.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
        if self._recv_buffer_bytes > 0:
            try:
                sock.setsockopt(
                    socket_module.SOL_SOCKET, socket_module.SO_RCVBUF, self._recv_buffer_bytes
                )
            except OSError:
                _log.warning(
                    "failed to set SO_RCVBUF; using the OS default",
                    extra={"requested_bytes": self._recv_buffer_bytes},
                )
        try:
            sock.bind((host, port))
            sock.setblocking(False)
            self._actual_recv_buffer_bytes = sock.getsockopt(
                socket_module.SOL_SOCKET, socket_module.SO_RCVBUF
            )
            _log.info(
                "udp syslog socket bound",
                extra={
                    "host": host,
                    "port": port,
                    "requested_rcvbuf_bytes": self._recv_buffer_bytes,
                    "actual_rcvbuf_bytes": self._actual_recv_buffer_bytes,
                },
            )
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _SyslogDatagramProtocol(self), sock=sock
            )
        except BaseException:
            sock.close()
            raise
        self._transport = transport  # type: ignore[assignment]

    @property
    def actual_recv_buffer_bytes(self) -> int | None:
        """The ``SO_RCVBUF`` size the OS actually granted, or ``None`` before :meth:`start`."""
        return self._actual_recv_buffer_bytes

    async def stop(self) -> None:
        """Close the socket and wait for in-flight ``on_event`` tasks to finish."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    @property
    def sockname(self) -> tuple[str | int, ...]:
        """The bound ``(host, port, ...)`` tuple. Raises if not started."""
        if self._transport is None:
            raise RuntimeError("listener not started")
        return self._transport.get_extra_info("sockname")

    @property
    def socket(self) -> object:
        """The underlying UDP socket (e.g. to tune ``SO_RCVBUF``). Raises if not started."""
        if self._transport is None:
            raise RuntimeError("listener not started")
        return self._transport.get_extra_info("socket")

    def _on_datagram(self, data: bytes, peer: str) -> None:
        """Count the datagram and schedule its delivery as a ``RawEvent``."""
        EVENTS_RECEIVED.labels(transport="udp").inc()
        BYTES_RECEIVED.labels(transport="udp").inc(len(data))
        event = make_raw_event(data, source_id=self._source_id, transport="udp", peer=peer)
        task = asyncio.create_task(self._dispatch(event))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _dispatch(self, event: RawEvent) -> None:
        """Await the user callback for one event, logging any failure."""
        assert self._on_event is not None
        try:
            await self._on_event(event)
        except Exception:  # noqa: BLE001 - a bad callback must not kill the listener
            _log.exception("udp syslog on_event failed", extra={"event_uid": event.event_uid})
