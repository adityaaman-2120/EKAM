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
"""

from __future__ import annotations

import datetime as dt
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
_ALLOWED_MODES = ("a",)


class DlqStats(TypedDict):
    """Aggregate dead-letter counts, shaped for the API."""

    total: int
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
        for record in self._iter_all_records():
            by_reason[record.reason] += 1
            by_stage[record.stage] += 1
        return DlqStats(
            total=sum(by_reason.values()),
            by_reason=dict(by_reason),
            by_stage=dict(by_stage),
        )

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
        return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%d")

    @staticmethod
    def _open(path: Path, mode: str) -> IO[str]:
        """Open a partition file, refusing any mode that could overwrite content."""
        assert mode in _ALLOWED_MODES, f"dlq is append-only; mode {mode!r} is forbidden"
        return path.open(mode, encoding="utf-8")
