"""Silver-tier compaction — the fix for the small-file problem.

THE SMALL-FILE PROBLEM
----------------------
A streaming sink flushes on a short timer so fresh events become queryable
quickly (:mod:`ulpf.sinks.parquet_sink` defaults to 60 s). Over a day that is
~1400 flushes per ``(date, source_type)`` partition, most only a few hundred KB
— thousands of tiny Parquet files.

Query engines collapse under this. Every file carries a fixed per-file cost
regardless of size: open it, read and parse the footer (schema + per-row-group
statistics + column chunk offsets), plan the read, then issue small scattered
I/Os. With 128 MB files that overhead is amortised over millions of rows and is
invisible. With 200 KB files the engine spends almost all of its wall-clock on
file *bookkeeping* and almost none on reading column data: a scan that should
take a second takes minutes, object-store LIST/GET counts (and bills) explode,
and Arrow/Spark schedulers choke on the task count.

Compaction periodically rewrites each partition's ``part-*.parquet`` files into
a few large ones (target ~128 MB), preserving every row and unifying any schema
drift across the inputs, then deletes the originals. It is pure housekeeping:
idempotent, safe to re-run, and it never changes query *results* — only their
speed.

SAFETY
------
Each output file is written to a ``.<name>.tmp`` sibling and then atomically
:func:`os.replace`-d into place; the source files are deleted only after every
output has been renamed. If the process is killed between the renames and the
deletes, the next compaction pass simply re-merges the survivors — no data is
lost. Run compaction from a single scheduler so passes never overlap.

WHEN A PARTITION HAS ONLY ONE FILE ALREADY
-------------------------------------------
By default (``min_files=2``, ``ulpf compact --min-files``) a partition with
fewer than 2 ``part-*.parquet`` files is left untouched — merging one file into
one file is pure churn on a real, healthy partition. On a small or synthetic
dataset (a demo, a short manual test run) every partition may only ever
accumulate exactly one file before the run ends, so ``compact_all`` reports
"0 partitions compacted" even though the merge/split/schema-unification logic
was never exercised. Pass ``min_files=1`` (CLI: ``--min-files 1``) to force a
rewrite of single-file partitions too, purely to demonstrate the path end to
end; it is never needed for real operational use.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from ulpf.config.settings import Settings

_log = logging.getLogger(__name__)

_TARGET_FILE_BYTES = 128 * 1024 * 1024  # 128 MiB
_MIN_TARGET_BYTES = 4096
_COMPRESSION = "zstd"
_HOURLY = 3600.0


@dataclass(frozen=True)
class CompactionResult:
    """What one :meth:`Compactor.compact` call did to one partition."""

    date: str
    source_type: str
    files_before: int
    files_after: int
    rows: int
    bytes_before: int
    bytes_after: int
    compacted: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DEFAULT_MIN_FILES = 2


class Compactor:
    """Merges the many small Parquet files in a silver partition into a few large ones."""

    def __init__(
        self,
        settings: Settings,
        *,
        target_file_bytes: int = _TARGET_FILE_BYTES,
        min_files: int = DEFAULT_MIN_FILES,
    ) -> None:
        """Configure against ``storage.silver_path`` and a target output file size.

        Args:
            settings: Supplies ``storage.silver_path``.
            target_file_bytes: Roughly how large each output file should be.
            min_files: A partition with fewer than this many ``part-*.parquet``
                files is left untouched (``compacted=False``) — merging one
                file into one file is pure churn. The default, 2, is the
                housekeeping threshold: any partition with 2+ files benefits.
                Pass ``1`` to force a rewrite of single-file partitions too
                (e.g. to demonstrate the merge path end-to-end against a small
                or synthetic dataset where every partition only ever
                accumulates one file).
        """
        self._silver = Path(settings.storage.silver_path)
        self._target = max(int(target_file_bytes), _MIN_TARGET_BYTES)
        self._min_files = max(int(min_files), 1)

    def partitions(self, *, date: str | None = None) -> Iterator[tuple[str, str]]:
        """Yield every ``(date, source_type)`` partition under the silver root."""
        if not self._silver.is_dir():
            return
        for date_dir in sorted(self._silver.glob("date=*")):
            partition_date = date_dir.name.removeprefix("date=")
            if not date_dir.is_dir() or (date is not None and partition_date != date):
                continue
            for source_dir in sorted(date_dir.glob("source_type=*")):
                if source_dir.is_dir():
                    yield partition_date, source_dir.name.removeprefix("source_type=")

    def compact_all(self, *, date: str | None = None) -> list[CompactionResult]:
        """Compact every partition (optionally only those for ``date``).

        A partition that fails to compact (e.g. an unreadable file someone
        dropped in) is logged and skipped; the others are still done.
        """
        results: list[CompactionResult] = []
        for partition_date, source_type in self.partitions(date=date):
            try:
                results.append(self.compact(partition_date, source_type))
            except Exception:  # noqa: BLE001 - one bad partition must not block the rest
                _log.exception(
                    "failed to compact date=%s source_type=%s", partition_date, source_type
                )
        return results

    def compact(self, date: str, source_type: str) -> CompactionResult:
        """Merge one partition's ``part-*.parquet`` files into >=1 target-sized files."""
        part_dir = self._silver / f"date={date}" / f"source_type={source_type}"
        parts = sorted(part_dir.glob("part-*.parquet"))
        bytes_before = sum(p.stat().st_size for p in parts)

        if len(parts) < self._min_files:  # below the configured merge threshold
            rows = _row_count(parts[0]) if parts else 0
            return CompactionResult(
                date,
                source_type,
                len(parts),
                len(parts),
                rows,
                bytes_before,
                bytes_before,
                compacted=False,
            )

        merged = merge_tables([pq.ParquetFile(p).read() for p in parts])
        rows_per_file = _rows_per_file(merged.num_rows, bytes_before, self._target)
        new_files = _write_slices(part_dir, merged, rows_per_file)

        for part in parts:  # originals go only after every output is safely in place
            part.unlink()

        bytes_after = sum(p.stat().st_size for p in new_files)
        _log.info(
            "compacted partition",
            extra={
                "date": date,
                "source_type": source_type,
                "files_before": len(parts),
                "files_after": len(new_files),
                "rows": merged.num_rows,
            },
        )
        return CompactionResult(
            date,
            source_type,
            len(parts),
            len(new_files),
            merged.num_rows,
            bytes_before,
            bytes_after,
            compacted=True,
        )


# -- table merge (schema-drift tolerant) -------------------------------


def merge_tables(tables: list[pa.Table]) -> pa.Table:
    """Concatenate tables, filling missing columns with nulls and promoting types.

    A column whose type genuinely conflicts across files (e.g. ``int64`` in one,
    ``string`` in another) is coerced to a JSON string in every table so the
    merge cannot fail.
    """
    try:
        return pa.concat_tables(tables, promote_options="permissive")
    except (pa.ArrowInvalid, pa.ArrowTypeError, pa.ArrowNotImplementedError):
        conflicted = _conflicting_columns(tables)
        return pa.concat_tables(
            [_stringify_columns(table, conflicted) for table in tables],
            promote_options="permissive",
        )


def _conflicting_columns(tables: list[pa.Table]) -> set[str]:
    """Names of columns that have more than one non-null Arrow type across ``tables``."""
    seen: dict[str, set[str]] = {}
    for table in tables:
        for field in table.schema:
            if not pa.types.is_null(field.type):
                seen.setdefault(field.name, set()).add(str(field.type))
    return {name for name, types in seen.items() if len(types) > 1}


def _stringify_columns(table: pa.Table, names: set[str]) -> pa.Table:
    """Replace each named column in ``table`` with a JSON-string version."""
    for name in names:
        if name not in table.column_names:
            continue
        values = table.column(name).to_pylist()
        as_json = [None if v is None else json.dumps(v, default=str) for v in values]
        index = table.column_names.index(name)
        table = table.set_column(index, pa.field(name, pa.string()), pa.array(as_json, pa.string()))
    return table


# -- writing -----------------------------------------------------------


def _rows_per_file(rows: int, bytes_before: int, target_bytes: int) -> int:
    """Rows to put in each output file so each is roughly ``target_bytes`` on disk."""
    if rows <= 0:
        return 1
    avg_row_bytes = max(bytes_before / rows, 1.0)
    return max(1, int(target_bytes / avg_row_bytes))


def _write_slices(part_dir: Path, table: pa.Table, rows_per_file: int) -> list[Path]:
    """Write ``table`` as consecutive slices, each via a temp file + atomic rename."""
    written: list[Path] = []
    for start in range(0, table.num_rows, rows_per_file):
        chunk = table.slice(start, rows_per_file)
        final = part_dir / f"part-{uuid.uuid4().hex}.parquet"
        tmp = part_dir / f".{final.name}.tmp"
        pq.write_table(chunk, tmp, compression=_COMPRESSION)
        os.replace(tmp, final)
        written.append(final)
    return written


def _row_count(path: Path) -> int:
    """Row count from a Parquet file's footer (no data read)."""
    return int(pq.ParquetFile(path).metadata.num_rows)


# -- background task --------------------------------------------------


async def run_periodic_compaction(
    settings: Settings,
    *,
    interval_seconds: float = _HOURLY,
    iterations: int | None = None,
    on_result: Callable[[CompactionResult], None] | None = None,
) -> None:
    """Compact every silver partition once per ``interval_seconds`` (hourly by default).

    Runs until cancelled, or for ``iterations`` passes (tests). A failing pass is
    logged and the loop continues — housekeeping must not take the process down.
    """
    compactor = Compactor(settings)
    completed = 0
    while True:
        try:
            for result in compactor.compact_all():
                if on_result is not None:
                    on_result(result)
        except Exception:  # noqa: BLE001 - a housekeeping loop must survive any partition
            _log.exception("compaction pass failed; will retry next interval")
        completed += 1
        if iterations is not None and completed >= iterations:
            return
        await asyncio.sleep(interval_seconds)
