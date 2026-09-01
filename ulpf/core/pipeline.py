"""Pipeline orchestrator: wires ingest -> stages -> sinks together.

A :class:`Pipeline` owns a :class:`~ulpf.ingest.queue.BoundedEventQueue` and a
:class:`~ulpf.sinks.dlq.DeadLetterQueue`, and runs a pool of worker tasks. Each
worker pulls a :class:`~ulpf.core.models.RawEvent` off the queue and passes it
through every registered :class:`Stage` in order, timing each stage into
``ulpf_stage_latency_seconds``.

Failure handling per the project rules:

* A stage returning ``None`` deliberately drops the event — processing stops, no
  error.
* Any exception raised by a stage sends the *original* event to the dead-letter
  queue tagged with that stage's name and the exception type, and the worker
  moves on to the next event. One bad event never kills a worker.

Shutdown is graceful: :meth:`Pipeline.stop` waits for the queue to drain, stops
the workers, then flushes every stage that exposes a ``flush`` method (e.g.
:class:`RawStoreStage`) so no buffered write is lost.

Stages registered so far: :class:`RawStoreStage` (bronze/evidence write) then
:class:`ParseStage` (format detection, syslog-envelope stripping, field
extraction). :class:`NoOpStage` is kept as a placeholder for normalize/enrich.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections import deque
from typing import Final, Protocol, TypeAlias, runtime_checkable

from ulpf.config.settings import Settings
from ulpf.core.errors import ParseError, PipelineStoppedError
from ulpf.core.metrics import EVENTS_PARSED, PARSE_SUCCESS_RATE, timed
from ulpf.core.models import NormalizedEvent, ParsedEvent, RawEvent
from ulpf.ingest.queue import BoundedEventQueue
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)

Event: TypeAlias = RawEvent | ParsedEvent | NormalizedEvent

_SHUTDOWN: Final = object()  # sentinel put on the queue to wake a worker to exit


@runtime_checkable
class Stage(Protocol):
    """A pipeline stage: transform an event, or return ``None`` to drop it."""

    name: str

    async def process(self, event: Event) -> Event | None:
        """Process one event; return the (possibly new) event, or ``None`` to stop it."""
        ...


class RawStoreStage:
    """Stage 1: append the raw event to the bronze/evidence store."""

    name = "raw_store"

    def __init__(self, raw_store: RawStore) -> None:
        """Wrap an already-configured :class:`RawStore`."""
        self._store = raw_store

    async def process(self, event: Event) -> Event:
        """Persist ``event`` verbatim and pass it through unchanged."""
        assert isinstance(event, RawEvent)
        self._store.write(event)
        return event

    def flush(self) -> None:
        """Flush buffered bronze writes to disk (called on shutdown)."""
        self._store.flush()


class NoOpStage:
    """A stage that returns the event untouched. Placeholder for real stages."""

    name = "noop"

    async def process(self, event: Event) -> Event:
        """Return ``event`` unchanged."""
        return event


class ParseStage:
    """Stage 2: sniff format, strip the syslog envelope, extract fields.

    Wraps :class:`~ulpf.parse.coordinator.ParseCoordinator`. On
    :class:`~ulpf.core.errors.ParseError` the event is written to the
    dead-letter queue with ``stage="parse"`` and dropped (``process`` returns
    ``None``) so the worker continues. Each attempt updates
    ``ulpf_parse_success_rate``; each success bumps ``ulpf_events_parsed_total``.
    """

    name = "parse"

    def __init__(
        self, settings: Settings, coordinator: ParseCoordinator, *, window: int = 1000
    ) -> None:
        """Wire the coordinator and a dead-letter queue for parse failures."""
        self._coordinator = coordinator
        self._dlq = DeadLetterQueue(settings)
        self._outcomes: deque[int] = deque(maxlen=window)

    async def process(self, event: Event) -> Event | None:
        """Return a :class:`ParsedEvent`, or ``None`` after dead-lettering a failure."""
        assert isinstance(event, RawEvent)
        try:
            parsed = self._coordinator.parse(event)
        except ParseError as exc:
            self._observe(success=False)
            self._dlq.write(
                event,
                reason=str(exc.detail.get("reason") or "parse_error"),
                stage=self.name,
                detail=dict(exc.detail),
            )
            _log.warning(
                "parse failed; event dead-lettered",
                extra={"event_uid": event.event_uid, "detail": exc.detail},
            )
            return None
        self._observe(success=True)
        EVENTS_PARSED.labels(source_type=parsed.source_type or "unknown").inc()
        return parsed

    def _observe(self, *, success: bool) -> None:
        """Record one parse outcome and refresh ``ulpf_parse_success_rate``."""
        self._outcomes.append(1 if success else 0)
        PARSE_SUCCESS_RATE.set(sum(self._outcomes) / len(self._outcomes))


class Pipeline:
    """Runs events from a bounded queue through an ordered list of stages."""

    def __init__(self, settings: Settings, stages: list[Stage]) -> None:
        """Build the queue and DLQ from ``settings``; take an ordered stage list."""
        self._settings = settings
        self._stages = list(stages)
        self.queue = BoundedEventQueue(settings)
        self.dlq = DeadLetterQueue(settings)
        self._workers: list[asyncio.Task[None]] = []
        self._stopped = False

    def start(self) -> None:
        """Launch ``settings.pipeline.worker_count`` worker tasks."""
        if self._workers:
            raise RuntimeError("pipeline already started")
        self._stopped = False
        for worker_id in range(self._settings.pipeline.worker_count):
            self._workers.append(asyncio.create_task(self._worker(worker_id)))

    async def submit(self, event: Event) -> None:
        """Enqueue an event for processing, applying backpressure when full."""
        if self._stopped:
            raise PipelineStoppedError("pipeline is shutting down")
        await self.queue.put_with_backpressure(event)

    async def stop(self) -> None:
        """Drain the queue, stop the workers, then flush every stage's sink."""
        if self._stopped:
            return
        self._stopped = True
        await self.queue.join()
        for _ in self._workers:
            await self.queue.put_with_backpressure(_SHUTDOWN)
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        await self._flush_stages()

    # -- internals -------------------------------------------------------

    async def _worker(self, worker_id: int) -> None:
        """Consume the queue until a shutdown sentinel is received."""
        while True:
            item = await self.queue.get()
            try:
                if item is _SHUTDOWN:
                    return
                await self._run_stages(item)
            finally:
                self.queue.task_done()

    async def _run_stages(self, event: Event) -> None:
        """Run one event through every stage; DLQ on exception, stop on ``None``."""
        current: Event = event
        for stage in self._stages:
            try:
                with timed(stage.name):
                    result = await stage.process(current)
            except Exception as exc:  # noqa: BLE001 - isolate stage failures
                self._to_dlq(event, stage.name, exc)
                return
            if result is None:
                return
            current = result

    def _to_dlq(self, event: Event, stage_name: str, exc: BaseException) -> None:
        """Route a failed event to the dead-letter queue with context."""
        if not isinstance(event, RawEvent):
            _log.error("cannot dead-letter a non-raw event", extra={"stage": stage_name})
            return
        self.dlq.write(
            event, reason=type(exc).__name__, stage=stage_name, detail={"error": str(exc)}
        )
        _log.warning(
            "stage failed; event dead-lettered",
            extra={"stage": stage_name, "event_uid": event.event_uid, "error": str(exc)},
        )

    async def _flush_stages(self) -> None:
        """Call ``flush()`` on every stage that has one (sync or async)."""
        for stage in self._stages:
            flush = getattr(stage, "flush", None)
            if not callable(flush):
                continue
            outcome = flush()
            if inspect.isawaitable(outcome):
                await outcome
