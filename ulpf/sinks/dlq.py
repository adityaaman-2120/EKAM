"""Dead-letter queue — the visible failure channel.

When a line cannot be sniffed, parsed, or normalized, ULPF routes it here
instead of guessing. That is deliberate:

* **Silent mis-parsing is the dangerous failure.** A parser that "succeeds" on a
  log it does not actually understand emits normalized events with wrong fields
  — a wrong source IP, a ``deny`` recorded as an ``allow``, a timestamp a year
  off. Those propagate downstream and quietly corrupt detections, dashboards,
  and investigations while every health check stays green.
* **A visible DLQ rate is a healthy signal.** A non-zero, monitored dead-letter
  rate points operators straight at the source/stage that needs a parser fix,
  and the original bytes sit here intact and replayable. Under-claiming (send it
  to the DLQ) beats over-claiming (emit a confident wrong answer).

Records are :class:`~ulpf.core.models.DeadLetter` objects written as NDJSON, one
per line, append-only, partitioned by write date under
``dlq_path/date=YYYY-MM-DD/``. Every write increments
``ulpf_dead_letter_total{stage,reason}``.

RESOLUTION
----------
``ulpf dlq replay`` (:mod:`ulpf.cli.dlq`) re-runs dead letters through the
pipeline, typically after a new/fixed source YAML now handles them. A
successful replay is recorded by *appending* a resolution record to a second,
also append-only file (``resolved.ndjson``) rather than rewriting or deleting
the original entry — the failure stays in the audit trail forever; only its
current status changes. :meth:`DeadLetterQueue.resolved_event_uids` folds that
file into the set of event UIDs no longer considered outstanding.
"""

from __future__ import annotations

import datetime as dt
import json
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO, Any, TypedDict

from ulpf.config.settings import Settings
from ulpf.core.metrics import DEAD_LETTER
from ulpf.core.models import DeadLetter, RawEvent

_PARTITION_GLOB = "date=*"
_PARTITION_FILE = "deadletters.ndjson"
_RESOLVED_FILE = "resolved.ndjson"
_ALLOWED_MODES = ("a",)


class DlqStats(TypedDict):
    """Aggregate dead-letter counts, shaped for the API."""

    total: int
    resolved: int
    unresolved: int
    by_reason: dict[str, int]
    by_stage: dict[str, int]


class DeadLetterQueue:
    """Append-only NDJSON store of events that failed a pipeline stage."""

    def __init__(self, settings: Settings, *, clock: Callable[[], int] = time.time_ns) -> None:
        """Configure the queue.

        Args:
            settings: Supplies ``storage.dlq_path``.
            clock: UTC epoch-nanoseconds source (injectable for tests).
        """
        self._dlq: Path = Path(settings.storage.dlq_path)
        self._clock = clock

    def write(
        self,
        raw_event: RawEvent,
        reason: str,
        stage: str,
        detail: dict[str, Any] | None = None,
    ) -> DeadLetter:
        """Persist ``raw_event`` as a dead letter and bump ``ulpf_dead_letter_total``.

        Args:
            raw_event: The event that could not be processed.
            reason: Short machine-readable cause, e.g. ``"grok_timeout"``.
            stage: Pipeline stage that failed, e.g. ``"parse"``.
            detail: Optional structured context (candidates tried, offsets, ...).

        Returns:
            The persisted :class:`DeadLetter` record.
        """
        record = DeadLetter(
            event_uid=raw_event.event_uid,
            raw=raw_event.raw,
            raw_hash=raw_event.raw_hash,
            reason=reason,
            stage=stage,
            detail=detail or {},
            ts_ns=self._clock(),
        )
        path = self._partition_file(self._date_of(record.ts_ns))
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._open(path, "a") as handle:
            handle.write(record.model_dump_json() + "\n")
        DEAD_LETTER.labels(stage=stage, reason=reason).inc()
        return record

    def iter_recent(self, limit: int) -> Iterator[DeadLetter]:
        """Yield the most recent dead letters, newest first, up to ``limit``.

        Files are append-ordered, so the newest records are the last lines of
        the newest date partition.
        """
        if limit <= 0:
            return
        yielded = 0
        for partition in sorted(self._dlq.glob(_PARTITION_GLOB), reverse=True):
            path = partition / _PARTITION_FILE
            if not path.exists():
                continue
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            for line in reversed(lines):
                yield DeadLetter.model_validate_json(line)
                yielded += 1
                if yielded >= limit:
                    return

    def stats(self) -> DlqStats:
        """Return the total plus dead-letter counts grouped by reason and by stage."""
        by_reason: Counter[str] = Counter()
        by_stage: Counter[str] = Counter()
        total = 0
        resolved = self.resolved_event_uids()
        resolved_count = 0
        for record in self._iter_all_records():
            total += 1
            by_reason[record.reason] += 1
            by_stage[record.stage] += 1
            if record.event_uid in resolved:
                resolved_count += 1
        return DlqStats(
            total=total,
            resolved=resolved_count,
            unresolved=total - resolved_count,
            by_reason=dict(by_reason),
            by_stage=dict(by_stage),
        )

    def iter_entries(
        self,
        *,
        reason: str | None = None,
        since_ns: int | None = None,
        unresolved_only: bool = False,
    ) -> Iterator[DeadLetter]:
        """Yield stored dead letters, oldest first, optionally filtered.

        Args:
            reason: only entries whose ``reason`` matches exactly.
            since_ns: only entries with ``ts_ns >= since_ns``.
            unresolved_only: skip entries already marked resolved (see
                :meth:`mark_resolved`).
        """
        resolved: set[str] = self.resolved_event_uids() if unresolved_only else set()
        for record in self._iter_all_records():
            if reason is not None and record.reason != reason:
                continue
            if since_ns is not None and record.ts_ns < since_ns:
                continue
            if unresolved_only and record.event_uid in resolved:
                continue
            yield record

    def mark_resolved(self, event_uid: str, *, detail: dict[str, Any] | None = None) -> None:
        """Record that ``event_uid`` was successfully replayed.

        Appends to a separate, also append-only file — the original dead-letter
        entry is never rewritten or deleted, so the failure stays in the audit
        trail even after it is resolved.
        """
        path = self._dlq / _RESOLVED_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"event_uid": event_uid, "resolved_ts_ns": self._clock(), "detail": detail or {}}
        with self._open(path, "a") as handle:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    def resolved_event_uids(self) -> set[str]:
        """Every ``event_uid`` that has ever been marked resolved."""
        path = self._dlq / _RESOLVED_FILE
        if not path.exists():
            return set()
        uids: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                uids.add(json.loads(line)["event_uid"])
        return uids

    def _iter_all_records(self) -> Iterator[DeadLetter]:
        """Yield every stored dead letter across all partitions, chronologically."""
        for partition in sorted(self._dlq.glob(_PARTITION_GLOB)):
            path = partition / _PARTITION_FILE
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    yield DeadLetter.model_validate_json(line)

    def _partition_file(self, date_str: str) -> Path:
        """Path to the NDJSON file for a ``YYYY-MM-DD`` partition."""
        return self._dlq / f"date={date_str}" / _PARTITION_FILE

    @staticmethod
    def _date_of(ts_ns: int) -> str:
        """UTC ``YYYY-MM-DD`` for an epoch-nanoseconds timestamp."""
        seconds = ts_ns // 1_000_000_000
        return dt.datetime.fromtimestamp(seconds, dt.UTC).strftime("%Y-%m-%d")

    @staticmethod
    def _open(path: Path, mode: str) -> IO[str]:
        """Open a partition file, refusing any mode that could overwrite content."""
        assert mode in _ALLOWED_MODES, f"dlq is append-only; mode {mode!r} is forbidden"
        return path.open(mode, encoding="utf-8")
