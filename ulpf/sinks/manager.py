"""``SinkManager`` — fan one normalized event out to every enabled sink at once.

The pipeline's final stage. For each :class:`~ulpf.core.models.NormalizedEvent`
it calls every registered sink's ``write`` **concurrently** (``asyncio.gather``)
and collects a per-sink success/failure:

* **Required sinks** (Parquet, by default — the silver/ML-ready tier) must
  succeed. If *any* required sink fails, the event is **dead-lettered**
  (``stage="sinks"``, ``reason="required_sink_failed"``) — it is never silently
  lost, even though the raw bytes are already safe in bronze and only a
  traceability stub (``event_uid`` + ``raw_hash``) travels with the DLQ entry.
* **Optional sinks** (ClickHouse, OpenSearch, Splunk HEC, by default) failing is
  logged and counted, but does **not** dead-letter the event — these are
  best-effort exports, not the record of truth.

A sink's own delivery contract still applies underneath this: ``ParquetSink``
writes are effectively synchronous local I/O (run off-thread here so one slow
flush cannot stall the others); ``ClickHouseSink`` may *block* a write under
sustained backpressure by design (see its module docstring) — marking it
required would combine "never drop, block instead" with the DLQ guarantee, and
the block simply wins (the event never reaches the point of being dead-lettered
because the write never returns); ``OpenSearchSink`` / ``SplunkHecSink`` never
raise for an eventual batch-delivery failure (they log-and-drop internally), so
marking them required would not do what you want — leave them optional.

Metrics: ``ulpf_sink_writes_total{sink,status="ok"|"failed"}`` and
``ulpf_sink_latency_seconds{sink}`` for every attempted write.

Graceful shutdown (:meth:`flush`, picked up automatically by
:class:`~ulpf.core.pipeline.Pipeline`'s shutdown) closes — and thereby flushes —
every registered sink, concurrently, best-effort.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from ulpf.config.settings import Settings
from ulpf.core.metrics import SINK_LATENCY, SINK_WRITES
from ulpf.core.models import NormalizedEvent, RawEvent
from ulpf.core.pipeline import Event
from ulpf.sinks.clickhouse_sink import ClickHouseSink
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.opensearch_sink import OpenSearchSink
from ulpf.sinks.parquet_sink import ParquetSink
from ulpf.sinks.splunk_hec_sink import SplunkHecSink

_log = logging.getLogger(__name__)

_AsyncFn = Callable[[], Awaitable[None]]
_AsyncWrite = Callable[[NormalizedEvent], Awaitable[None]]


@dataclass(frozen=True)
class SinkResult:
    """The outcome of one sink writing one event."""

    name: str
    required: bool
    ok: bool
    elapsed_seconds: float
    error: BaseException | None = None


class SinkHandle:
    """Uniform async ``start``/``write``/``close`` wrapper around one sink.

    Lets :class:`SinkManager` treat a synchronous sink (:class:`ParquetSink`,
    run off-thread) and the async network sinks identically.
    """

    def __init__(
        self,
        name: str,
        *,
        required: bool,
        write: _AsyncWrite,
        start: _AsyncFn | None = None,
        close: _AsyncFn | None = None,
    ) -> None:
        """Wrap one sink's lifecycle behind three optional async callables."""
        self.name = name
        self.required = required
        self._write = write
        self._start = start
        self._close = close

    async def start(self) -> None:
        """Call the wrapped sink's start hook, if it has one."""
        if self._start is not None:
            await self._start()

    async def write(self, event: NormalizedEvent) -> None:
        """Write one event through the wrapped sink."""
        await self._write(event)

    async def close(self) -> None:
        """Call the wrapped sink's close hook, if it has one (flush + release)."""
        if self._close is not None:
            await self._close()

    @classmethod
    def for_async_sink(cls, name: str, sink: Any, *, required: bool) -> SinkHandle:
        """Wrap a sink that already exposes async ``start``/``write``/``close``."""
        return cls(name, required=required, write=sink.write, start=sink.start, close=sink.close)

    @classmethod
    def for_sync_sink(cls, name: str, sink: Any, *, required: bool) -> SinkHandle:
        """Wrap a synchronous sink (:class:`ParquetSink`); its calls run off-thread."""
        return cls(
            name,
            required=required,
            write=lambda event: asyncio.to_thread(sink.write, event),
            close=lambda: asyncio.to_thread(sink.close),
        )


class SinkManager:
    """Fans a normalized event out to every registered sink, concurrently."""

    name = "sinks"

    def __init__(
        self,
        settings: Settings,
        *,
        dlq: DeadLetterQueue | None = None,
        clock: Callable[[], float] = time.perf_counter,
    ) -> None:
        """Start with no sinks registered; use :meth:`register` or :meth:`from_settings`."""
        self._settings = settings
        self._dlq = dlq or DeadLetterQueue(settings)
        self._clock = clock
        self._handles: list[SinkHandle] = []

    @classmethod
    def from_settings(cls, settings: Settings, *, dlq: DeadLetterQueue | None = None) -> SinkManager:
        """Build the default sink set: Parquet required, the network sinks optional.

        The network sinks are always registered (cheaply — no I/O happens until
        :meth:`start`); each one no-ops on its own when its own
        ``settings.<sink>.enabled`` is False, so nothing extra needs gating here.
        """
        manager = cls(settings, dlq=dlq)
        manager.register(SinkHandle.for_sync_sink("parquet", ParquetSink(settings), required=True))
        manager.register(
            SinkHandle.for_async_sink("clickhouse", ClickHouseSink(settings), required=False)
        )
        manager.register(
            SinkHandle.for_async_sink("opensearch", OpenSearchSink(settings), required=False)
        )
        manager.register(
            SinkHandle.for_async_sink("splunk_hec", SplunkHecSink(settings), required=False)
        )
        return manager

    def register(self, handle: SinkHandle) -> None:
        """Add one sink to the fan-out set."""
        self._handles.append(handle)

    @property
    def sink_names(self) -> list[str]:
        """Names of every registered sink, in registration order."""
        return [handle.name for handle in self._handles]

    @property
    def required_sink_names(self) -> list[str]:
        """Names of the sinks whose failure dead-letters the event."""
        return [handle.name for handle in self._handles if handle.required]

    # -- lifecycle ----------------------------------------------------

    async def start(self) -> None:
        """Start every registered sink concurrently; a failure is logged, not fatal."""
        outcomes = await asyncio.gather(
            *(handle.start() for handle in self._handles), return_exceptions=True
        )
        for handle, outcome in zip(self._handles, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                _log.error("sink %r failed to start: %s", handle.name, outcome)

    async def flush(self) -> None:
        """Close (and thereby flush) every sink concurrently. Called on pipeline shutdown."""
        outcomes = await asyncio.gather(
            *(handle.close() for handle in self._handles), return_exceptions=True
        )
        for handle, outcome in zip(self._handles, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                _log.warning("error closing sink %r: %s", handle.name, outcome)

    async def close(self) -> None:
        """Alias for :meth:`flush`."""
        await self.flush()

    # -- the pipeline stage --------------------------------------------

    async def process(self, event: Event) -> Event | None:
        """Write ``event`` to every sink; dead-letter it iff a required sink failed."""
        assert isinstance(event, NormalizedEvent)
        if not self._handles:
            return event

        results = await asyncio.gather(*(self._write_one(handle, event) for handle in self._handles))
        for result in results:
            self._record(result, event)

        failed_required = [result for result in results if result.required and not result.ok]
        if failed_required:
            self._dead_letter(event, failed_required)
            return None
        return event

    async def _write_one(self, handle: SinkHandle, event: NormalizedEvent) -> SinkResult:
        """Run one sink's write, isolating its failure from every other sink."""
        started = self._clock()
        try:
            await handle.write(event)
        except Exception as exc:  # noqa: BLE001 - one sink's failure must not affect the others
            return SinkResult(handle.name, handle.required, False, self._clock() - started, exc)
        return SinkResult(handle.name, handle.required, True, self._clock() - started)

    def _record(self, result: SinkResult, event: NormalizedEvent) -> None:
        """Emit metrics and a log line for one sink's outcome."""
        SINK_WRITES.labels(sink=result.name, status="ok" if result.ok else "failed").inc()
        SINK_LATENCY.labels(sink=result.name).observe(result.elapsed_seconds)
        if not result.ok:
            _log.log(
                logging.ERROR if result.required else logging.WARNING,
                "sink %r failed to write event %s: %s",
                result.name, event.event_uid, result.error,
            )

    def _dead_letter(self, event: NormalizedEvent, failed: list[SinkResult]) -> None:
        """Route to the DLQ: a required sink failed, so the event must not be silently lost."""
        self._dlq.write(
            _raw_stub(event),
            reason="required_sink_failed",
            stage=self.name,
            detail={
                "source_type": event.source_type,
                "failed_sinks": [result.name for result in failed],
                "errors": {result.name: str(result.error) for result in failed},
            },
        )
        _log.error(
            "event %s dead-lettered: required sink(s) failed: %s",
            event.event_uid, [result.name for result in failed],
        )


def _raw_stub(event: NormalizedEvent) -> RawEvent:
    """A minimal :class:`RawEvent` carrying the traceability keys for the DLQ.

    The original bytes are already in the bronze store keyed by ``raw_hash``; a
    sink-delivery failure does not need to re-persist them.
    """
    return RawEvent(
        event_uid=event.event_uid,
        raw=b"",
        raw_hash=event.raw_hash,
        raw_len=0,
        ingest_time_ns=event.ingest_time_ns,
        source_id=event.source_type,
        transport="file",
    )
