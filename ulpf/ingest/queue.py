"""Bounded, back-pressuring intake queue for ULPF.

**Backpressure** means slowing a producer down when the downstream consumer
cannot keep up, instead of letting an in-memory buffer grow without limit until
the process is OOM-killed. Here the producers are the network listeners
(syslog UDP/TCP/TLS, HTTP, file tail) and the consumer is the processing
pipeline. When the pipeline falls behind, :meth:`BoundedEventQueue.put_with_backpressure`
makes the listener *wait* for room rather than accepting more than it can hold.

**Why dropping is unacceptable.** ULPF ingests perimeter security telemetry. The
events an analyst needs most during an incident — port-scan storms, DDoS floods,
brute-force bursts — are exactly the ones that arrive fastest and would be first
to be discarded by a "drop on overflow" queue. Losing them destroys evidence,
breaks the raw-to-normalized traceability guarantee, and blinds detection when it
matters most. It also violates the project rule that no event is ever dropped
silently. So a full queue does one of two things, both accountable:

* ``drop_policy="block"`` (default): the producer awaits free space (optionally
  bounded by a ``timeout``, after which it raises so the caller can push the
  backpressure further upstream, e.g. stop reading the socket).
* ``drop_policy="dlq"``: overflow is handed to the dead-letter queue, where it is
  still persisted and counted — never ``/dev/null``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any, Literal

from ulpf.config.settings import Settings
from ulpf.core.errors import IngestError
from ulpf.core.metrics import DEAD_LETTER, QUEUE_BACKPRESSURE_WAITS, QUEUE_DEPTH

DropPolicy = Literal["block", "dlq"]
DlqHandler = Callable[[Any], Awaitable[None]]


class PutOutcome(StrEnum):
    """Result of :meth:`BoundedEventQueue.put_with_backpressure`."""

    ENQUEUED = "enqueued"
    DEAD_LETTERED = "dead_lettered"


class BoundedEventQueue:
    """An ``asyncio.Queue`` with a hard capacity and explicit overflow handling.

    No global state: the wrapped queue and its configuration live on the
    instance, and ``Settings`` is injected by the caller.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        drop_policy: DropPolicy = "block",
        dlq_handler: DlqHandler | None = None,
    ) -> None:
        """Create the queue sized from ``settings.ingest.queue_max_size``.

        Args:
            settings: Provides the maximum queue size.
            drop_policy: ``"block"`` waits for space; ``"dlq"`` diverts overflow.
            dlq_handler: Async callback receiving an overflowed item. Required
                when ``drop_policy == "dlq"``.

        Raises:
            ValueError: If ``drop_policy == "dlq"`` but no handler was given.
        """
        if drop_policy == "dlq" and dlq_handler is None:
            raise ValueError("drop_policy='dlq' requires a dlq_handler")
        self.max_size: int = settings.ingest.queue_max_size
        self.drop_policy: DropPolicy = drop_policy
        self._dlq_handler = dlq_handler
        self._queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=self.max_size)

    def depth(self) -> int:
        """Return the current item count and publish it to ``ulpf_queue_depth``."""
        size = self._queue.qsize()
        QUEUE_DEPTH.set(size)
        return size

    def full(self) -> bool:
        """Whether the queue is at capacity."""
        return self._queue.full()

    async def put_with_backpressure(self, item: Any, timeout: float | None = None) -> PutOutcome:
        """Enqueue ``item``, waiting for space instead of dropping it.

        Fast path: enqueue immediately if there is room. Otherwise apply
        backpressure — increment ``ulpf_queue_backpressure_waits_total`` and wait
        up to ``timeout`` seconds (indefinitely if ``None``). If the wait times
        out, ``"block"`` policy raises :class:`IngestError` and ``"dlq"`` policy
        routes the item to the dead-letter handler.

        Returns:
            ``PutOutcome.ENQUEUED`` or ``PutOutcome.DEAD_LETTERED``.
        """
        try:
            self._queue.put_nowait(item)
            self.depth()
            return PutOutcome.ENQUEUED
        except asyncio.QueueFull:
            pass

        QUEUE_BACKPRESSURE_WAITS.inc()
        try:
            await asyncio.wait_for(self._queue.put(item), timeout)
        except TimeoutError:
            return await self._on_timeout(item, timeout)
        self.depth()
        return PutOutcome.ENQUEUED

    async def _on_timeout(self, item: Any, timeout: float | None) -> PutOutcome:
        """Resolve a backpressure wait that exceeded ``timeout`` per drop policy."""
        detail: dict[str, object] = {"max_size": self.max_size, "timeout_s": timeout}
        if self.drop_policy == "block":
            raise IngestError("intake queue full; backpressure timeout exceeded", detail=detail)
        assert self._dlq_handler is not None  # guaranteed by __init__
        await self._dlq_handler(item)
        DEAD_LETTER.labels(stage="ingest", reason="queue_full").inc()
        return PutOutcome.DEAD_LETTERED

    async def get(self) -> Any:
        """Remove and return the next item, refreshing the depth gauge."""
        item = await self._queue.get()
        self.depth()
        return item

    def task_done(self) -> None:
        """Mark a previously :meth:`get`-ed item as fully processed."""
        self._queue.task_done()

    async def join(self) -> None:
        """Block until every enqueued item has been marked done."""
        await self._queue.join()

    def __len__(self) -> int:
        """Current queue size, with no gauge side effect."""
        return self._queue.qsize()
