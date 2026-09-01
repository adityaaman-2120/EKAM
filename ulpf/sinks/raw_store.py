"""Bronze tier — the evidence store.

``RawStore`` is the first thing that touches an ingested event and the last word
on what was actually received. Every raw event is appended verbatim (base64 of
the original bytes, plus its SHA-256) to a gzipped NDJSON file partitioned by
UTC ingest date::

    <bronze_path>/date=YYYY-MM-DD/events.ndjson.gz

**Append-only.** This module opens files in exactly two modes: ``"ab"`` (append)
and ``"rb"`` (read). It never uses ``"wb"``, ``"w"``, ``"r+"``, ``"a+"`` or any
other mode that can truncate or rewrite bytes already on disk. That rule is
enforced by an assertion in :meth:`RawStore._gzip`, the single place a file is
opened. Appending to a gzip stream simply concatenates a new gzip *member*;
readers (including this one) decode the members transparently, so the store
grows without any existing byte ever changing. The raw event is evidence — it is
written once and only ever read again.

Writes are buffered in memory and committed by :meth:`RawStore.flush`, which is
also called automatically once the buffer reaches ``max_buffered_records`` or
``max_buffer_seconds`` have elapsed since the last commit. Read/verify/iterate
operations flush first so on-disk data is authoritative.
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import IO

from ulpf.config.settings import Settings
from ulpf.core.models import RawEvent, sha256_hex

_PARTITION_GLOB = "date=*"
_PARTITION_FILE = "events.ndjson.gz"
_ALLOWED_MODES = ("ab", "rb")


class RawStore:
    """Append-only, gzip-NDJSON store of raw events, partitioned by ingest date."""

    def __init__(
        self,
        settings: Settings,
        *,
        max_buffered_records: int = 1000,
        max_buffer_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the store.

        Args:
            settings: Supplies ``storage.bronze_path``.
            max_buffered_records: Auto-flush once this many records are buffered.
            max_buffer_seconds: Auto-flush once this long has passed since the
                last flush.
            clock: Monotonic time source (injectable for tests).
        """
        self._bronze: Path = Path(settings.storage.bronze_path)
        self._max_records = max_buffered_records
        self._max_seconds = max_buffer_seconds
        self._clock = clock
        self._buffer: dict[str, list[bytes]] = {}
        self._buffered_count = 0
        self._last_flush = clock()

    # -- writing -----------------------------------------------------------

    def write(self, raw_event: RawEvent) -> None:
        """Buffer ``raw_event`` for its ingest-date partition; auto-flush if due."""
        date_str = self._date_of(raw_event.ingest_time_ns)
        self._buffer.setdefault(date_str, []).append(self._encode(raw_event))
        self._buffered_count += 1
        if self._should_autoflush():
            self.flush()

    def flush(self) -> None:
        """Append every buffered record to its partition file and clear the buffer."""
        for date_str, lines in self._buffer.items():
            if not lines:
                continue
            path = self._partition_file(date_str)
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._gzip(path, "ab") as handle:
                for line in lines:
                    handle.write(line)
        self._buffer.clear()
        self._buffered_count = 0
        self._last_flush = self._clock()

    def close(self) -> None:
        """Flush any pending records. Safe to call more than once."""
        self.flush()

    def __enter__(self) -> RawStore:
        """Enter a context that flushes on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Flush buffered records when leaving the context."""
        self.flush()

    # -- reading -----------------------------------------------------------

    def read_by_uid(self, event_uid: str) -> RawEvent | None:
        """Return the stored event with ``event_uid``, or ``None`` if absent."""
        self.flush()
        for record in self._scan_records():
            if record["event_uid"] == event_uid:
                return self._record_to_event(record)
        return None

    def iter_all(self, date: str | dt.date | None = None) -> Iterator[RawEvent]:
        """Yield every stored event, optionally restricted to one ingest date.

        Args:
            date: ``"YYYY-MM-DD"`` string or ``datetime.date``; ``None`` for all.
        """
        self.flush()
        date_str = date.isoformat() if isinstance(date, dt.date) else date
        for record in self._scan_records(date_str):
            yield self._record_to_event(record)

    def verify(self, event_uid: str) -> bool:
        """Re-read the stored event, re-hash its raw bytes, compare to ``raw_hash``.

        Returns ``False`` if the event is not found or the digest does not match.
        """
        self.flush()
        for record in self._scan_records():
            if record["event_uid"] != event_uid:
                continue
            raw = base64.b64decode(record["raw_b64"])
            return sha256_hex(raw) == record["raw_hash"]
        return False

    # -- internals -------------------------------------------------------

    def _should_autoflush(self) -> bool:
        """Whether the record-count or elapsed-time threshold has been reached."""
        if self._buffered_count >= self._max_records:
            return True
        return (self._clock() - self._last_flush) >= self._max_seconds

    def _encode(self, event: RawEvent) -> bytes:
        """Serialize ``event`` to one newline-terminated NDJSON record (bytes)."""
        record = {
            "event_uid": event.event_uid,
            "raw_hash": event.raw_hash,
            "raw_b64": base64.b64encode(event.raw).decode("ascii"),
            "raw_len": event.raw_len,
            "ingest_time_ns": event.ingest_time_ns,
            "source_id": event.source_id,
            "transport": event.transport,
            "peer": event.peer,
        }
        return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    @staticmethod
    def _record_to_event(record: dict[str, object]) -> RawEvent:
        """Rebuild a :class:`RawEvent` from a decoded NDJSON record."""
        return RawEvent(
            event_uid=str(record["event_uid"]),
            raw=base64.b64decode(str(record["raw_b64"])),
            raw_hash=str(record["raw_hash"]),
            raw_len=int(record["raw_len"]),  # type: ignore[arg-type]
            ingest_time_ns=int(record["ingest_time_ns"]),  # type: ignore[arg-type]
            source_id=str(record["source_id"]),
            transport=record["transport"],  # type: ignore[arg-type]
            peer=record["peer"],  # type: ignore[arg-type]
        )

    def _scan_records(self, date: str | None = None) -> Iterator[dict[str, object]]:
        """Yield decoded records from the matching partition file(s)."""
        for partition in sorted(self._bronze.glob(_PARTITION_GLOB)):
            if not partition.is_dir():
                continue
            if date is not None and partition.name != f"date={date}":
                continue
            path = partition / _PARTITION_FILE
            if path.exists():
                yield from self._read_lines(path)

    def _read_lines(self, path: Path) -> Iterator[dict[str, object]]:
        """Yield one parsed JSON object per non-empty line of a gzip NDJSON file."""
        with self._gzip(path, "rb") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if line:
                    yield json.loads(line)

    def _partition_file(self, date_str: str) -> Path:
        """Path to the NDJSON.gz file for the given ``YYYY-MM-DD`` partition."""
        return self._bronze / f"date={date_str}" / _PARTITION_FILE

    @staticmethod
    def _date_of(ingest_time_ns: int) -> str:
        """UTC ``YYYY-MM-DD`` string for an epoch-nanoseconds timestamp."""
        seconds = ingest_time_ns // 1_000_000_000
        return dt.datetime.fromtimestamp(seconds, dt.UTC).strftime("%Y-%m-%d")

    @staticmethod
    def _gzip(path: Path, mode: str) -> IO[bytes]:
        """Open a gzip file, refusing any mode that could overwrite existing bytes.

        The store is append-only: only ``"ab"`` and ``"rb"`` are ever allowed.
        """
        assert mode in _ALLOWED_MODES, f"raw_store is append-only; mode {mode!r} is forbidden"
        return gzip.open(path, mode)
