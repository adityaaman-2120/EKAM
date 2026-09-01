"""Asyncio UDP syslog listener (RFC 3164 / RFC 5426 style datagrams).

**UDP syslog is lossy by design.** The transport has no handshake, no
acknowledgements, no retransmission, and no sequence numbers. A datagram dropped
by a congested link, a full kernel receive buffer, or an overrun NIC simply
never arrives, and nothing on either side records that it existed. This listener
therefore counts exactly what it *received* — ``ulpf_events_received_total`` and
``ulpf_bytes_received_total`` — but it can never account for what it did *not*
receive. That is a property of the protocol, not a defect here; sources that
need lossless delivery must use the TCP or TLS listeners.

The bytes of each datagram are passed through untouched: no decoding, no newline
handling, no charset guessing. Each datagram becomes exactly one
:class:`~ulpf.core.models.RawEvent` via
:func:`~ulpf.integrity.hashing.make_raw_event`, hashed before anything else sees
it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED
from ulpf.core.models import RawEvent
from ulpf.integrity.hashing import make_raw_event

_log = logging.getLogger(__name__)

OnEvent = Callable[[RawEvent], Awaitable[None]]


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

    def __init__(self, source_id: str = "syslog-udp") -> None:
        """Create a listener that tags every event with ``source_id``."""
        self._source_id = source_id
        self._transport: asyncio.DatagramTransport | None = None
        self._on_event: OnEvent | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    async def start(self, host: str, port: int, on_event: OnEvent) -> None:
        """Bind to ``host:port`` and deliver each datagram to ``on_event``.

        Pass ``port=0`` to bind an ephemeral port; read it back from
        :attr:`sockname`.
        """
        loop = asyncio.get_running_loop()
        self._on_event = on_event
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogDatagramProtocol(self),
            local_addr=(host, port),
        )
        self._transport = transport  # type: ignore[assignment]

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
