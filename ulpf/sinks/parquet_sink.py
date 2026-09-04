"""Silver tier — columnar Parquet, the "ML-ready" store (requirement *h*).

WHY COLUMNAR PARQUET *IS* "ML-READY"
-----------------------------------
Feature extraction and model training do not read whole events. They read a
*few columns* across *millions of rows*: "give me ``src_ip``, ``dst_port``,
``bytes_out`` and ``time`` for every event on 2026-09-04". Parquet stores each
column contiguously, so that query touches only those four column chunks and
skips the other ~80 entirely — I/O is proportional to the *features used*, not to
the row width. On top of that Parquet brings, for free:

* **compression that actually compresses** — a column of ``class_uid`` values or
  repeated ``source_type`` strings is dictionary/RLE-encoded then ZSTD-packed,
  typically 5-15x smaller than the equivalent NDJSON;
* **predicate & projection push-down** — engines (DuckDB, Polars, Spark,
  pyarrow.dataset) read column statistics in the footer and skip whole row
  groups / files that cannot match a filter;
* **vectorised, zero-copy scans** into Arrow / NumPy — no per-row JSON parsing,
  no Python object per field;
* **partition pruning** — laying files out as
  ``date=YYYY-MM-DD/source_type=<name>/`` means a date- or source-scoped feature
  job never opens the other partitions.

A row-oriented store (the bronze NDJSON) is the right shape for *evidence* — you
replay whole events. It is the wrong shape for *analytics* — you would parse
every field of every row to read three of them. This sink is the bridge.

SHAPE
-----
:class:`ParquetSink` buffers :class:`~ulpf.core.models.NormalizedEvent` objects
and flushes them to
``silver_path/date=YYYY-MM-DD/source_type=<name>/part-<uuid>.parquet`` when the
buffer reaches ``max_rows`` (default 10 000) or ``flush_interval_seconds``
(default 60) have elapsed. Compression is ZSTD.

``source_type`` is written **both** in the Hive path and as a required data
column (see below), so read a whole tree with an explicit unified schema, e.g.::

    files = list(silver.rglob("*.parquet"))
    schema = pa.unify_schemas([pq.ParquetFile(f).schema_arrow for f in files],
                              promote_options="permissive")
    table = ds.dataset([str(f) for f in files], schema=schema,
                       partitioning=None).to_table()

The OCSF record is flattened to columns (nested keys joined with ``.``; lists
become JSON strings). Seventeen **core columns are always present** with fixed
types:

    event_uid, raw_hash, time, class_uid, category_uid, activity_id, type_uid,
    severity_id, source_type, src_ip, src_port, dst_ip, dst_port, protocol,
    action_id, bytes_in, bytes_out

The ``unmapped`` and ``enrichments`` objects are sparse and high-cardinality, so
they are stored whole as JSON strings in ``unmapped_json`` / ``enrichments_json``
rather than exploded into thousands of mostly-null columns.

SCHEMA DRIFT
------------
Each flush builds its file's schema from *its own* rows, so a new source or a
new optional field simply adds a column to later files. Nothing fails; readers
(``pyarrow.dataset``, DuckDB, Spark) unify schemas across files on read. A
column whose values disagree on type across a batch is coerced to a JSON string
rather than raising.
"""

from __future__ import annotations

import datetime as dt
import json
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from ulpf.config.settings import Settings
from ulpf.core.models import NormalizedEvent

_DEFAULT_MAX_ROWS = 10_000
_DEFAULT_FLUSH_SECONDS = 60.0
_COMPRESSION = "zstd"

# Core columns: always emitted, with a fixed Arrow type even when a whole batch
# has no value for them.
_CORE_SCHEMA: dict[str, pa.DataType] = {
    "event_uid": pa.string(),
    "raw_hash": pa.string(),
    "time": pa.int64(),
    "class_uid": pa.int64(),
    "category_uid": pa.int64(),
    "activity_id": pa.int64(),
    "type_uid": pa.int64(),
    "severity_id": pa.int64(),
    "source_type": pa.string(),
    "src_ip": pa.string(),
    "src_port": pa.int64(),
    "dst_ip": pa.string(),
    "dst_port": pa.int64(),
    "protocol": pa.string(),
    "action_id": pa.int64(),
    "bytes_in": pa.int64(),
    "bytes_out": pa.int64(),
}
CORE_COLUMNS: tuple[str, ...] = tuple(_CORE_SCHEMA)

_JSON_OBJECT_KEYS = ("unmapped", "enrichments")


class ParquetSink:
    """Buffers normalized events and writes partitioned, ZSTD Parquet files."""

    def __init__(
        self,
        settings: Settings,
        *,
        max_rows: int = _DEFAULT_MAX_ROWS,
        flush_interval_seconds: float = _DEFAULT_FLUSH_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Configure the sink.

        Args:
            settings: Supplies ``storage.silver_path``.
            max_rows: Flush once this many rows are buffered (across all partitions).
            flush_interval_seconds: Flush once this long has passed since the last flush.
            clock: Monotonic time source (injectable for tests).
        """
        self._silver = Path(settings.storage.silver_path)
        self._max_rows = max(int(max_rows), 1)
        self._interval = max(float(flush_interval_seconds), 0.0)
        self._clock = clock

        self._buffer: dict[tuple[str, str], list[dict[str, Any]]] = {}
        self._buffered = 0
        self._last_flush = clock()
        self.files_written = 0
        self.rows_written = 0

    # -- writing ---------------------------------------------------------

    def write(self, event: NormalizedEvent) -> None:
        """Buffer one event for its ``(date, source_type)`` partition; auto-flush if due."""
        date = _epoch_ns_to_date(event.ocsf.get("time") or event.ingest_time_ns)
        key = (date, event.source_type or "unknown")
        self._buffer.setdefault(key, []).append(_row(event))
        self._buffered += 1
        if self._buffered >= self._max_rows or self._time_due():
            self.flush()

    def flush(self) -> list[Path]:
        """Write every buffered partition to its own Parquet file; return the paths."""
        written: list[Path] = []
        for (date, source_type), rows in self._buffer.items():
            if not rows:
                continue
            part_dir = self._silver / f"date={date}" / f"source_type={_slug(source_type)}"
            part_dir.mkdir(parents=True, exist_ok=True)
            path = part_dir / f"part-{uuid.uuid4().hex}.parquet"
            pq.write_table(_build_table(rows), path, compression=_COMPRESSION)
            written.append(path)
            self.files_written += 1
            self.rows_written += len(rows)
        self._buffer.clear()
        self._buffered = 0
        self._last_flush = self._clock()
        return written

    def close(self) -> list[Path]:
        """Flush any pending rows. Safe to call more than once."""
        return self.flush()

    def __enter__(self) -> ParquetSink:
        """Enter a context that flushes on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Flush buffered rows when leaving the context."""
        self.flush()

    # -- internals -----------------------------------------------------

    @property
    def buffered_rows(self) -> int:
        """Rows currently held in memory (not yet on disk)."""
        return self._buffered

    def _time_due(self) -> bool:
        """Whether the time-since-last-flush threshold has been reached."""
        if self._interval <= 0 or self._buffered == 0:
            return False
        return (self._clock() - self._last_flush) >= self._interval


# -- row shaping ---------------------------------------------------------


def _row(event: NormalizedEvent) -> dict[str, Any]:
    """Flatten one normalized event into a single columnar row."""
    ocsf = event.ocsf
    row: dict[str, Any] = {}
    _flatten(ocsf, "", row)
    row.update(core_row(event))  # core columns are authoritative

    row["unmapped_json"] = _json_or_none(ocsf.get("unmapped"))
    row["enrichments_json"] = _json_or_none(ocsf.get("enrichments") or event.enrichment)
    return row


def core_row(event: NormalizedEvent) -> dict[str, Any]:
    """The 17 fixed core columns, pulled from well-known OCSF locations."""
    ocsf = event.ocsf
    src = ocsf.get("src_endpoint") or {}
    dst = ocsf.get("dst_endpoint") or {}
    conn = ocsf.get("connection_info") or {}
    traffic = ocsf.get("traffic") or {}
    return {
        "event_uid": event.event_uid,
        "raw_hash": event.raw_hash,
        "time": _as_int(ocsf.get("time")),
        "class_uid": _as_int(ocsf.get("class_uid")),
        "category_uid": _as_int(ocsf.get("category_uid")),
        "activity_id": _as_int(ocsf.get("activity_id")),
        "type_uid": _as_int(ocsf.get("type_uid")),
        "severity_id": _as_int(ocsf.get("severity_id")),
        "source_type": event.source_type,
        "src_ip": _as_str(src.get("ip")),
        "src_port": _as_int(src.get("port")),
        "dst_ip": _as_str(dst.get("ip")),
        "dst_port": _as_int(dst.get("port")),
        "protocol": _as_str(conn.get("protocol_name") or conn.get("protocol_num")),
        "action_id": _as_int(ocsf.get("action_id")),
        "bytes_in": _as_int(traffic.get("bytes_in")),
        "bytes_out": _as_int(traffic.get("bytes_out")),
    }


def _flatten(obj: dict[str, Any], prefix: str, out: dict[str, Any]) -> None:
    """Recursively flatten ``obj`` into ``out`` (dotted keys; lists -> JSON strings)."""
    for key, value in obj.items():
        if prefix == "" and key in _JSON_OBJECT_KEYS:
            continue  # emitted separately as *_json string columns
        col = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            if value:
                _flatten(value, col, out)
        elif isinstance(value, (list, tuple)):
            out[col] = _json_or_none(list(value))
        else:
            out[col] = value


# -- Arrow table construction (schema-drift tolerant) ------------------


def _build_table(rows: list[dict[str, Any]]) -> pa.Table:
    """Build one Arrow table: fixed-type core columns + inferred drift columns."""
    columns: dict[str, pa.Array] = {
        name: pa.array([row.get(name) for row in rows], type=arrow_type)
        for name, arrow_type in _CORE_SCHEMA.items()
    }
    drift = sorted({key for row in rows for key in row} - _CORE_SCHEMA.keys())
    for name in drift:
        columns[name] = _safe_array([row.get(name) for row in rows])
    return pa.table(columns)


def _safe_array(values: list[Any]) -> pa.Array:
    """Infer an Arrow array; fall back to JSON strings if the column is mixed-type."""
    try:
        arr = pa.array(values)
    except (pa.ArrowInvalid, pa.ArrowTypeError, pa.ArrowNotImplementedError):
        arr = pa.array([None if v is None else _json_or_none(v) for v in values], type=pa.string())
    if pa.types.is_null(arr.type):
        arr = arr.cast(pa.string())
    return arr


# -- scalar helpers ----------------------------------------------------


def _json_or_none(value: Any) -> str | None:
    """Compact JSON for a non-empty value, else ``None`` (keeps sparse columns sparse)."""
    if not value:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _as_int(value: Any) -> int | None:
    """Coerce to ``int`` (accepting digit strings); ``None`` for anything else."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _as_str(value: Any) -> str | None:
    """``str(value)`` or ``None``."""
    return None if value is None else str(value)


def _epoch_ns_to_date(epoch_ns: Any) -> str:
    """UTC ``YYYY-MM-DD`` for an epoch-nanoseconds value (now if unusable)."""
    try:
        seconds = int(epoch_ns) // 1_000_000_000
        return dt.datetime.fromtimestamp(seconds, dt.UTC).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError, OverflowError):
        return dt.datetime.now(dt.UTC).strftime("%Y-%m-%d")


def _slug(value: str) -> str:
    """Filesystem-safe partition value."""
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value) or "unknown"
