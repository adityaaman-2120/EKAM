"""Tests for :mod:`ulpf.sinks.compaction` and the ``ulpf compact`` command."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from ulpf.cli import compact as compact_cli
from ulpf.cli.main import app
from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.models import NormalizedEvent
from ulpf.sinks.compaction import Compactor, run_periodic_compaction
from ulpf.sinks.parquet_sink import ParquetSink

runner = CliRunner()
_DATE = "2026-09-01"
_SRC = "fortigate_traffic"
_TIME_NS = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z -> silver date=2026-09-01


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(silver_path=tmp_path / "silver"))


def _part_dir(tmp_path: Path, date: str = _DATE, source: str = _SRC) -> Path:
    return tmp_path / "silver" / f"date={date}" / f"source_type={source}"


def _write_part(
    part_dir: Path, rows: list[dict[str, Any]], schema: pa.Schema | None = None
) -> Path:
    part_dir.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=schema)
    path = part_dir / f"part-{uuid.uuid4().hex}.parquet"
    pq.write_table(table, path, compression="zstd")
    return path


def _rows(start: int, count: int) -> list[dict[str, Any]]:
    return [
        {"event_uid": f"e{i}", "n": i, "src_ip": "192.0.2.1"} for i in range(start, start + count)
    ]


def _part_files(part_dir: Path) -> list[Path]:
    return sorted(part_dir.glob("part-*.parquet"))


def _read_all(part_dir: Path) -> pa.Table:
    files = [str(p) for p in _part_files(part_dir)]
    return ds.dataset(files, partitioning=None).to_table()


def _normalized_event(uid: str) -> NormalizedEvent:
    """A minimal but real event, routed by :class:`ParquetSink` to date=2026-09-01."""
    ocsf = {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "type_uid": 400106,
        "severity_id": 1,
        "time": _TIME_NS,
        "src_endpoint": {"ip": "192.0.2.10", "port": 51000},
        "dst_endpoint": {"ip": "198.51.100.5", "port": 443},
    }
    return NormalizedEvent(
        event_uid=uid,
        raw_hash="a" * 64,
        ingest_time_ns=_TIME_NS,
        ocsf=ocsf,
        source_type=_SRC,
        mapping_version="1.0.0",
        enrichment={},
    )


# --------------------------------------------------------------------------
# end-to-end: real ParquetSink writes, real Compactor merges them
#
# Every other test in this file hand-builds its part-*.parquet files with
# pyarrow directly -- useful for exercising schema drift and edge cases in
# isolation, but it never proves the write path and the compaction path
# actually agree on what a partition looks like. This is the one integration
# test that pushes real NormalizedEvent objects through the real ParquetSink
# (with its flush threshold deliberately lowered, so a normal write burst
# reproduces the actual small-file problem) and then through the real
# Compactor, and checks nothing was lost across the round trip.


def test_write_then_compact_preserves_every_row_and_event_uid(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    # Production defaults are max_rows=10_000 / flush_interval_seconds=60 --
    # a single test run would never fill either, so it would always see the
    # "1 file, 0 partitions compacted" no-op ulpf compact --all just reported.
    # Lowering max_rows reproduces many small part files from ordinary writes.
    sink = ParquetSink(settings, max_rows=5)
    all_uids = {f"evt-{i}" for i in range(97)}  # not a multiple of 5: exercises a partial flush
    for uid in sorted(all_uids):
        sink.write(_normalized_event(uid))
    sink.close()

    part_dir = _part_dir(tmp_path, _DATE, _SRC)
    files_before = _part_files(part_dir)
    assert len(files_before) == 20  # ceil(97 / 5) -- the small-file problem, reproduced for real

    result = Compactor(settings).compact(_DATE, _SRC)

    assert result.compacted is True
    files_after = _part_files(part_dir)
    assert len(files_after) < len(files_before)
    assert result.files_before == 20 and result.rows == 97

    table = _read_all(part_dir)
    assert table.num_rows == 97  # row count identical
    assert set(table.column("event_uid").to_pylist()) == all_uids  # uid set unchanged


# --------------------------------------------------------------------------
# core compaction


def test_many_small_files_merge_into_one(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    for i in range(20):
        _write_part(part_dir, _rows(i * 5, 5))
    assert len(_part_files(part_dir)) == 20

    result = Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    assert result.compacted is True
    assert result.files_before == 20 and result.files_after == 1
    assert result.rows == 100
    assert len(_part_files(part_dir)) == 1
    table = pq.ParquetFile(_part_files(part_dir)[0]).read()
    assert table.num_rows == 100
    assert sum(table.column("n").to_pylist()) == sum(range(100))


def test_a_single_file_partition_is_left_untouched(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    only = _write_part(part_dir, _rows(0, 10))

    result = Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    assert result.compacted is False
    assert result.files_before == 1 and result.files_after == 1 and result.rows == 10
    assert _part_files(part_dir) == [only]  # same file, not rewritten


def test_min_files_one_forces_a_rewrite_of_a_single_file_partition(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    only = _write_part(part_dir, _rows(0, 10))

    result = Compactor(_settings(tmp_path), min_files=1).compact(_DATE, _SRC)

    assert result.compacted is True
    assert result.files_before == 1 and result.files_after == 1 and result.rows == 10
    rewritten = _part_files(part_dir)
    assert rewritten != [only]  # a new file, even though there was nothing to merge
    assert pq.ParquetFile(rewritten[0]).read().num_rows == 10


def test_missing_partition_is_a_clean_no_op(tmp_path: Path) -> None:
    result = Compactor(_settings(tmp_path)).compact(_DATE, "never_seen")
    assert result == result.__class__(_DATE, "never_seen", 0, 0, 0, 0, 0, compacted=False)


def test_every_row_and_column_is_preserved(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    all_uids = set()
    for i in range(4):
        rows = _rows(i * 7, 7)
        all_uids.update(r["event_uid"] for r in rows)
        _write_part(part_dir, rows)

    Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    table = _read_all(part_dir)
    assert table.num_rows == 28
    assert set(table.column("event_uid").to_pylist()) == all_uids
    assert set(table.column_names) == {"event_uid", "n", "src_ip"}


def test_no_temp_files_remain(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    for i in range(6):
        _write_part(part_dir, _rows(i * 3, 3))

    Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    assert list(part_dir.glob("*.tmp")) == []
    assert list(part_dir.glob(".*")) == []


# --------------------------------------------------------------------------
# schema drift + type conflicts


def test_schema_drift_across_files_is_unified(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    _write_part(part_dir, [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}])
    _write_part(part_dir, [{"a": 3, "c": 9.5}])

    Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    rows = {r["a"]: r for r in _read_all(part_dir).to_pylist()}
    assert set(rows[1]) == {"a", "b", "c"}
    assert rows[1]["b"] == "x" and rows[1]["c"] is None
    assert rows[3]["c"] == 9.5 and rows[3]["b"] is None


def test_a_type_conflict_is_coerced_to_json_string_not_fatal(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    _write_part(
        part_dir,
        [{"k": 1, "x": 10}],
        schema=pa.schema([("k", pa.int64()), ("x", pa.int64())]),
    )
    _write_part(
        part_dir,
        [{"k": 2, "x": "hello"}],
        schema=pa.schema([("k", pa.int64()), ("x", pa.string())]),
    )

    Compactor(_settings(tmp_path)).compact(_DATE, _SRC)

    table = _read_all(part_dir)
    assert str(table.schema.field("x").type) == "string"
    assert {json.loads(v) for v in table.column("x").to_pylist()} == {10, "hello"}


# --------------------------------------------------------------------------
# target size / splitting


def test_output_is_split_when_it_exceeds_the_target_size(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    # incompressible payloads so ZSTD cannot collapse the size estimate
    for _ in range(8):
        _write_part(
            part_dir,
            [{"event_uid": uuid.uuid4().hex, "blob": os.urandom(96).hex()} for _ in range(10)],
        )

    result = Compactor(_settings(tmp_path), target_file_bytes=4096).compact(_DATE, _SRC)

    assert result.compacted is True
    assert result.files_before == 8
    assert result.files_after >= 2  # 80 incompressible rows do not fit one 4 KB file
    assert _read_all(part_dir).num_rows == 80


# --------------------------------------------------------------------------
# compact_all


def test_compact_all_walks_every_partition_and_can_filter_by_date(tmp_path: Path) -> None:
    for date in ("2026-09-01", "2026-09-02"):
        for source in ("fortigate_traffic", "zeek_conn"):
            part_dir = _part_dir(tmp_path, date, source)
            for i in range(3):
                _write_part(part_dir, _rows(i * 2, 2))

    compactor = Compactor(_settings(tmp_path))

    all_results = compactor.compact_all()
    assert len(all_results) == 4
    assert all(r.files_before == 3 and r.files_after == 1 for r in all_results)

    one_day = Compactor(_settings(tmp_path)).compact_all(date="2026-09-01")
    assert len(one_day) == 2
    assert {r.date for r in one_day} == {"2026-09-01"}


def test_compact_all_skips_an_unreadable_partition_and_does_the_rest(tmp_path: Path) -> None:
    good = _part_dir(tmp_path, _DATE, "good")
    for i in range(3):
        _write_part(good, _rows(i, 1))
    bad = _part_dir(tmp_path, _DATE, "bad")
    bad.mkdir(parents=True)
    (bad / "part-broken.parquet").write_bytes(b"this is not a parquet file")
    (bad / "part-alsobroken.parquet").write_bytes(b"nor is this")

    results = Compactor(_settings(tmp_path)).compact_all()

    assert [r.source_type for r in results] == ["good"]  # bad partition skipped
    assert results[0].files_after == 1
    assert len(list(bad.glob("part-*.parquet"))) == 2  # left as-is


# --------------------------------------------------------------------------
# CLI


@pytest.fixture
def populated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = _settings(tmp_path)
    for source in ("fortigate_traffic", "suricata_eve_alert"):
        part_dir = _part_dir(tmp_path, _DATE, source)
        for i in range(5):
            _write_part(part_dir, _rows(i * 4, 4))
    monkeypatch.setattr(compact_cli, "_load_settings", lambda: settings)
    return settings


def test_cli_compact_all_json(populated: Settings) -> None:
    result = runner.invoke(app, ["compact", "--all", "--json"])
    assert result.exit_code == 0

    rows = json.loads(result.stdout)
    assert len(rows) == 2
    assert all(r["files_before"] == 5 and r["files_after"] == 1 and r["compacted"] for r in rows)


def test_cli_compact_all_table(populated: Settings) -> None:
    result = runner.invoke(app, ["compact", "--all"])
    assert result.exit_code == 0
    assert "partition(s) compacted" in result.stdout
    assert "fortigate_traffic" in result.stdout


def test_cli_compact_by_date(populated: Settings) -> None:
    result = runner.invoke(app, ["compact", "--date", _DATE, "--json"])
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)) == 2

    empty = runner.invoke(app, ["compact", "--date", "1999-01-01", "--json"])
    assert empty.exit_code == 0 and json.loads(empty.stdout) == []


def test_cli_min_files_forces_single_file_partitions_to_compact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    for source in ("fortigate_traffic", "suricata_eve_alert"):
        _write_part(_part_dir(tmp_path, _DATE, source), _rows(0, 3))
    monkeypatch.setattr(compact_cli, "_load_settings", lambda: settings)

    default = runner.invoke(app, ["compact", "--all", "--json"])
    assert json.loads(default.stdout) and all(
        not r["compacted"] for r in json.loads(default.stdout)
    )

    forced = runner.invoke(app, ["compact", "--all", "--min-files", "1", "--json"])
    rows = json.loads(forced.stdout)
    assert len(rows) == 2 and all(r["compacted"] for r in rows)


# --------------------------------------------------------------------------
# background task


async def test_periodic_compaction_runs_and_stops_after_iterations(tmp_path: Path) -> None:
    part_dir = _part_dir(tmp_path)
    for i in range(10):
        _write_part(part_dir, _rows(i * 2, 2))

    seen: list[str] = []
    await run_periodic_compaction(
        _settings(tmp_path),
        interval_seconds=0.0,
        iterations=2,
        on_result=lambda r: seen.append(r.source_type),
    )

    assert len(_part_files(part_dir)) == 1  # merged on the first pass
    assert seen == [_SRC, _SRC]  # both passes reported the partition (2nd is a no-op)
