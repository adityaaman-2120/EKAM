"""Tests for :mod:`ulpf.sinks.duckdb_query` — the zero-infrastructure lake query."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.sinks.duckdb_query import LakeQuery, ReadOnlyViolation

_BASE_NS = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(silver_path=tmp_path / "silver", dlq_path=tmp_path / "dlq")
    )


def _ev(uid: str, source: str, time_ns: int, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "event_uid": uid,
        "raw_hash": "h" * 64,
        "time": time_ns,
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "type_uid": 400106,
        "severity_id": 1,
        "source_type": source,
        "src_ip": "192.0.2.10",
        "src_port": 51000,
        "dst_ip": "198.51.100.5",
        "dst_port": 443,
        "protocol": "tcp",
        "action_id": 1,
        "bytes_in": 100,
        "bytes_out": 200,
        "unmapped_json": "{}",
        "enrichments_json": "{}",
    }
    row.update(overrides)
    return row


def _write_events(silver: Path, date: str, source: str, rows: list[dict[str, Any]]) -> Path:
    part_dir = silver / f"date={date}" / f"source_type={source}"
    part_dir.mkdir(parents=True, exist_ok=True)
    path = part_dir / f"part-{uuid.uuid4().hex}.parquet"
    pq.write_table(pa.Table.from_pylist(rows), path, compression="zstd")
    return path


def _write_dlq(dlq: Path, date: str, records: list[dict[str, Any]]) -> None:
    part_dir = dlq / f"date={date}"
    part_dir.mkdir(parents=True, exist_ok=True)
    with (part_dir / "deadletters.ndjson").open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


@pytest.fixture
def lake(tmp_path: Path):  # noqa: ANN201
    silver = tmp_path / "silver"
    _write_events(
        silver,
        "2026-09-01",
        "fortigate_traffic",
        [
            _ev("f1", "fortigate_traffic", _BASE_NS + 10, src_ip="10.0.0.1", bytes_out=500),
            _ev("f2", "fortigate_traffic", _BASE_NS + 20, src_ip="10.0.0.2"),
            _ev("f3", "fortigate_traffic", _BASE_NS + 30, src_ip="10.0.0.1", class_uid=4002),
        ],
    )
    _write_events(
        silver,
        "2026-09-02",
        "zeek_conn",
        [_ev("z1", "zeek_conn", _BASE_NS + 25, src_ip="203.0.113.9", bytes_in=9, bytes_out=1)],
    )
    _write_dlq(
        tmp_path / "dlq",
        "2026-09-01",
        [
            {
                "event_uid": "d1",
                "raw": "YWJj",
                "raw_hash": "x1",
                "reason": "parse_error",
                "stage": "parse",
                "detail": {"format": "kv"},
                "ts_ns": _BASE_NS,
            },
            {
                "event_uid": "d2",
                "raw": "ZGVm",
                "raw_hash": "x2",
                "reason": "ocsf_validation_failed",
                "stage": "validate",
                "detail": {"errors": ["bad"]},
                "ts_ns": _BASE_NS + 1,
            },
        ],
    )
    with LakeQuery(_settings(tmp_path)) as query:
        yield query


# --------------------------------------------------------------------------
# views


def test_events_and_dead_letters_views_are_queryable(lake: LakeQuery) -> None:
    assert lake.query("SELECT count(*) AS n FROM events")[0]["n"] == 4
    assert lake.query("SELECT count(*) AS n FROM dead_letters")[0]["n"] == 2


def test_hive_partition_columns_are_exposed(lake: LakeQuery) -> None:
    dates = sorted(row["date"] for row in lake.query("SELECT DISTINCT date FROM events"))
    assert dates == ["2026-09-01", "2026-09-02"]


def test_empty_lake_yields_typed_empty_views(tmp_path: Path) -> None:
    with LakeQuery(_settings(tmp_path)) as query:
        assert query.query("SELECT src_ip, source_type, date FROM events") == []
        assert query.query("SELECT stage, detail FROM dead_letters") == []
        assert query.recent() == []
        assert query.stats_by_source() == []


def test_schema_drift_between_part_files_is_unioned(tmp_path: Path) -> None:
    silver = tmp_path / "silver"
    _write_events(silver, "2026-09-01", "s", [_ev("a", "s", _BASE_NS)])
    _write_events(silver, "2026-09-01", "s", [_ev("b", "s", _BASE_NS + 1, extra_col=42)])

    with LakeQuery(_settings(tmp_path)) as query:
        assert query.query("SELECT count(*) AS n FROM events")[0]["n"] == 2
        drifted = query.query("SELECT event_uid FROM events WHERE extra_col = 42")
        assert [r["event_uid"] for r in drifted] == ["b"]


# --------------------------------------------------------------------------
# read-only guard


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE t (a INT)",
        "DROP VIEW events",
        "INSERT INTO events VALUES (1)",
        "DELETE FROM events",
        "UPDATE events SET src_ip = 'x'",
        "WITH c AS (SELECT 1) DELETE FROM events",
        "SELECT 1; DROP VIEW events",
        "PRAGMA version",
        "COPY (SELECT 1) TO 'out.csv'",
        "ATTACH 'x.db' AS y",
        "SET threads TO 1",
        "CALL pragma_version()",
        "   ",
    ],
)
def test_query_rejects_anything_that_is_not_a_read_only_select(lake: LakeQuery, sql: str) -> None:
    with pytest.raises(ReadOnlyViolation):
        lake.query(sql)


def test_query_allows_select_with_and_string_literals_that_look_scary(lake: LakeQuery) -> None:
    assert lake.query("SELECT 1 AS one")[0]["one"] == 1
    assert lake.query("WITH c AS (SELECT 2 AS n) SELECT n * 3 AS m FROM c")[0]["m"] == 6
    # 'drop table' only appears inside a string literal -> allowed
    rows = lake.query("SELECT count(*) AS n FROM events WHERE src_ip = 'drop table employees'")
    assert rows[0]["n"] == 0


def test_query_binds_positional_and_named_params(lake: LakeQuery) -> None:
    assert lake.query("SELECT ? + ? AS s", [40, 2])[0]["s"] == 42
    assert lake.query("SELECT $name AS n", {"name": "hi"})[0]["n"] == "hi"
    scoped = lake.query("SELECT event_uid FROM events WHERE source_type = ?", ["zeek_conn"])
    assert [r["event_uid"] for r in scoped] == ["z1"]


def test_query_before_connect_raises() -> None:
    with pytest.raises(RuntimeError):
        LakeQuery(_settings(Path("."))).query("SELECT 1")


# --------------------------------------------------------------------------
# convenience methods


def test_recent_returns_newest_first(lake: LakeQuery) -> None:
    rows = lake.recent(limit=3)
    assert [r["time"] for r in rows] == [_BASE_NS + 30, _BASE_NS + 25, _BASE_NS + 20]


def test_by_source_scopes_to_one_source(lake: LakeQuery) -> None:
    rows = lake.by_source("fortigate_traffic")
    assert len(rows) == 3
    assert {r["source_type"] for r in rows} == {"fortigate_traffic"}


def test_search_supports_equality_and_time_range(lake: LakeQuery) -> None:
    assert {r["event_uid"] for r in lake.search({"src_ip": "10.0.0.1"})} == {"f1", "f3"}
    assert {r["event_uid"] for r in lake.search({"class_uid": 4002})} == {"f3"}
    windowed = lake.search({"since_ns": _BASE_NS + 20, "until_ns": _BASE_NS + 26})
    assert {r["event_uid"] for r in windowed} == {"f2", "z1"}


def test_search_rejects_an_unknown_filter_column(lake: LakeQuery) -> None:
    with pytest.raises(ValueError):
        lake.search({"totally_made_up": 1})


def test_stats_by_source_aggregates_correctly(lake: LakeQuery) -> None:
    stats = {row["source_type"]: row for row in lake.stats_by_source()}
    assert stats["fortigate_traffic"]["events"] == 3
    assert stats["zeek_conn"]["events"] == 1
    # fortigate: (100+500) + (100+200) + (100+200) = 1200
    assert stats["fortigate_traffic"]["total_bytes"] == 1200
    assert stats["zeek_conn"]["total_bytes"] == 10
    assert stats["fortigate_traffic"]["distinct_src_ip"] == 2  # 10.0.0.1, 10.0.0.2
    # ordered by event count descending
    assert [r["source_type"] for r in lake.stats_by_source()][0] == "fortigate_traffic"


def test_timeseries_buckets_events_over_a_window(tmp_path: Path) -> None:
    silver = tmp_path / "silver"
    minute = 60 * 1_000_000_000
    times = [0, minute, 2 * minute, 2 * minute, 10 * minute, 11 * minute]
    _write_events(
        silver,
        "2026-09-01",
        "fortigate_traffic",
        [_ev(f"e{i}", "fortigate_traffic", _BASE_NS + t) for i, t in enumerate(times)],
    )

    with LakeQuery(_settings(tmp_path)) as query:
        per_minute = query.timeseries("1 minute", "1 hour")
        assert sum(r["events"] for r in per_minute) == 6
        assert all(
            isinstance(r["bucket"], str) and r["bucket"].startswith("2026-09-01T")
            for r in per_minute
        )

        # a 5-minute window from the newest bucket (minute 11) only covers minutes 10 & 11
        recent_only = query.timeseries("1 minute", "5 minutes")
        assert sum(r["events"] for r in recent_only) == 2

        with pytest.raises(ValueError):
            query.timeseries("fortnight", "1 hour")


# --------------------------------------------------------------------------
# dead letters + lifecycle


def test_dead_letters_detail_round_trips_as_json(lake: LakeQuery) -> None:
    rows = lake.query("SELECT stage, reason, detail FROM dead_letters ORDER BY ts_ns")
    assert [r["stage"] for r in rows] == ["parse", "validate"]
    assert json.loads(rows[1]["detail"])["errors"] == ["bad"]


def test_close_is_idempotent(tmp_path: Path) -> None:
    query = LakeQuery(_settings(tmp_path)).connect()
    query.close()
    query.close()  # no error
