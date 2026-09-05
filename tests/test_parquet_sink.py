"""Tests for :mod:`ulpf.sinks.parquet_sink`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.models import NormalizedEvent
from ulpf.sinks.parquet_sink import CORE_COLUMNS, ParquetSink

_SEP_1 = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z
_SEP_2 = 1_788_350_400_000_000_000  # 2026-09-02T12:00:00Z


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(silver_path=tmp_path / "silver"))


def _ocsf_4001(*, time_ns: int, src: str = "192.0.2.10", **extra: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "type_uid": 400106,
        "severity_id": 1,
        "time": time_ns,
        "src_endpoint": {"ip": src, "port": 51000},
        "dst_endpoint": {"ip": "198.51.100.5", "port": 443},
        "connection_info": {"protocol_name": "tcp", "protocol_num": 6, "uid": "c1"},
        "traffic": {"bytes_in": 1200, "bytes_out": 800, "packets": 10},
        "action_id": 1,
        "action": "Allowed",
        "firewall_rule": {"name": "allow-web"},
        "metadata": {"uid": "u", "log_hash": "h", "product": {"name": "FortiGate"}},
        "unmapped": {"transip": "203.0.113.9", "subtype": "forward"},
        "enrichments": {"network_context": {"direction": "outbound"}},
    }
    record.update(extra)
    return record


def _ne(uid: str, source_type: str, ocsf: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_uid=uid,
        raw_hash="a" * 64,
        ingest_time_ns=ocsf.get("time", _SEP_1),
        ocsf=ocsf,
        source_type=source_type,
        mapping_version="1.0.0",
        enrichment=ocsf.get("enrichments", {}),
    )


def _one_file(silver: Path) -> Path:
    files = list(silver.rglob("*.parquet"))
    assert len(files) == 1, files
    return files[0]


def _read(path: Path):  # noqa: ANN202 - pa.Table
    """Read one file directly (no Hive partition inference)."""
    return pq.ParquetFile(path).read()


# --------------------------------------------------------------------------
# partitioning + readback


def test_files_land_in_date_and_source_type_partitions(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    sink = ParquetSink(settings)
    sink.write(_ne("e1", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    sink.write(_ne("e2", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    sink.write(_ne("e3", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_2)))
    sink.write(_ne("e4", "suricata_eve_alert", _ocsf_4001(time_ns=_SEP_1)))

    written = sink.flush()
    silver = tmp_path / "silver"

    assert (silver / "date=2026-09-01" / "source_type=fortigate_traffic").is_dir()
    assert (silver / "date=2026-09-02" / "source_type=fortigate_traffic").is_dir()
    assert (silver / "date=2026-09-01" / "source_type=suricata_eve_alert").is_dir()
    assert len(written) == 3 and all(
        p.name.startswith("part-") and p.suffix == ".parquet" for p in written
    )

    by_dir = {p.parent.name + "/" + p.parent.parent.name: _read(p) for p in written}
    assert by_dir["source_type=fortigate_traffic/date=2026-09-01"].num_rows == 2
    assert by_dir["source_type=fortigate_traffic/date=2026-09-02"].num_rows == 1
    assert by_dir["source_type=suricata_eve_alert/date=2026-09-01"].num_rows == 1


def test_core_columns_are_always_present_and_correct(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with ParquetSink(settings) as sink:
        sink.write(_ne("evt-1", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))

    table = _read(_one_file(tmp_path / "silver"))
    assert set(CORE_COLUMNS).issubset(table.column_names)

    row = table.to_pylist()[0]
    assert row["event_uid"] == "evt-1" and row["raw_hash"] == "a" * 64
    assert row["source_type"] == "fortigate_traffic"
    assert (row["class_uid"], row["category_uid"], row["activity_id"]) == (4001, 4, 6)
    assert (row["type_uid"], row["severity_id"], row["action_id"]) == (400106, 1, 1)
    assert row["time"] == _SEP_1
    assert (row["src_ip"], row["src_port"]) == ("192.0.2.10", 51000)
    assert (row["dst_ip"], row["dst_port"]) == ("198.51.100.5", 443)
    assert row["protocol"] == "tcp"
    assert (row["bytes_in"], row["bytes_out"]) == (1200, 800)


def test_unmapped_and_enrichments_are_stored_as_json_strings(tmp_path: Path) -> None:
    with ParquetSink(_settings(tmp_path)) as sink:
        sink.write(_ne("e", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))

    table = _read(_one_file(tmp_path / "silver"))
    row = table.to_pylist()[0]

    assert isinstance(row["unmapped_json"], str)
    assert json.loads(row["unmapped_json"]) == {"transip": "203.0.113.9", "subtype": "forward"}
    assert json.loads(row["enrichments_json"]) == {"network_context": {"direction": "outbound"}}
    # not exploded into per-key columns
    assert "unmapped.transip" not in table.column_names
    assert "enrichments.network_context.direction" not in table.column_names


def test_nested_ocsf_fields_are_flattened_to_dotted_columns(tmp_path: Path) -> None:
    with ParquetSink(_settings(tmp_path)) as sink:
        sink.write(_ne("e", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))

    row = _read(_one_file(tmp_path / "silver")).to_pylist()[0]
    assert row["firewall_rule.name"] == "allow-web"
    assert row["metadata.product.name"] == "FortiGate"
    assert row["connection_info.uid"] == "c1"
    assert row["traffic.packets"] == 10
    assert row["action"] == "Allowed"


def test_files_are_zstd_compressed(tmp_path: Path) -> None:
    with ParquetSink(_settings(tmp_path)) as sink:
        sink.write(_ne("e", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))

    meta = pq.read_metadata(_one_file(tmp_path / "silver"))
    compressions = {
        meta.row_group(0).column(i).compression for i in range(meta.row_group(0).num_columns)
    }
    assert compressions == {"ZSTD"}


# --------------------------------------------------------------------------
# flush triggers


def test_flush_on_row_count(tmp_path: Path) -> None:
    sink = ParquetSink(_settings(tmp_path), max_rows=3)
    for i in range(3):
        sink.write(_ne(f"e{i}", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    assert sink.buffered_rows == 0 and sink.files_written == 1  # auto-flushed at 3

    sink.write(_ne("e3", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    assert sink.buffered_rows == 1 and sink.files_written == 1
    sink.close()
    assert sink.files_written == 2 and sink.rows_written == 4


def test_flush_on_time_interval(tmp_path: Path) -> None:
    now = [0.0]
    sink = ParquetSink(
        _settings(tmp_path), max_rows=10_000, flush_interval_seconds=10.0, clock=lambda: now[0]
    )
    sink.write(_ne("e0", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    assert sink.buffered_rows == 1 and sink.files_written == 0

    now[0] = 11.0
    sink.write(_ne("e1", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    assert sink.files_written == 1 and sink.buffered_rows == 0


# --------------------------------------------------------------------------
# schema drift


def test_new_column_in_a_later_file_does_not_fail_and_reads_back_unified(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    sink = ParquetSink(settings)

    sink.write(_ne("net-1", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    sink.flush()

    dns = {
        "class_uid": 4003,
        "category_uid": 4,
        "activity_id": 2,
        "type_uid": 400302,
        "severity_id": 1,
        "time": _SEP_1,
        "src_endpoint": {"ip": "192.0.2.9", "port": 40000},
        "query": {"hostname": "evil.example", "type": "A"},  # column absent from file 1
        "brand_new": {"nested": 7},  # a field never seen before
        "unmapped": {},
    }
    sink.write(_ne("dns-1", "zeek_dns", dns))
    sink.flush()

    files = list((tmp_path / "silver").rglob("*.parquet"))
    assert len(files) == 2

    second = _read(next(p for p in files if "zeek_dns" in str(p)))
    assert "query.hostname" in second.column_names and "brand_new.nested" in second.column_names

    # schema-drifted files read back with a unified schema (the standard idiom)
    unified_schema = pa.unify_schemas(
        [pq.ParquetFile(p).schema_arrow for p in files], promote_options="permissive"
    )
    unified = ds.dataset(
        [str(p) for p in files], schema=unified_schema, partitioning=None
    ).to_table()
    assert {"query.hostname", "brand_new.nested", "firewall_rule.name"}.issubset(
        unified.column_names
    )
    rows = {r["event_uid"]: r for r in unified.to_pylist()}
    assert rows["net-1"]["query.hostname"] is None  # older row has null for the new column
    assert rows["dns-1"]["query.hostname"] == "evil.example"


def test_a_type_conflicting_drift_column_is_coerced_to_json_string(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    sink = ParquetSink(settings)

    a = _ocsf_4001(time_ns=_SEP_1)
    a["firewall_rule"] = {"uid": 1}  # int here...
    b = _ocsf_4001(time_ns=_SEP_1)
    b["firewall_rule"] = {"uid": "outside_access_in"}  # ...string here
    sink.write(_ne("a", "fortigate_traffic", a))
    sink.write(_ne("b", "fortigate_traffic", b))
    sink.flush()

    table = _read(_one_file(tmp_path / "silver"))
    assert str(table.schema.field("firewall_rule.uid").type) == "string"
    values = table.column("firewall_rule.uid").to_pylist()
    assert [json.loads(v) for v in values] == [1, "outside_access_in"]


def test_all_null_core_column_keeps_its_fixed_type(tmp_path: Path) -> None:
    dns = {
        "class_uid": 4003,
        "category_uid": 4,
        "activity_id": 2,
        "type_uid": 400302,
        "severity_id": 1,
        "time": _SEP_1,
        "src_endpoint": {"ip": "192.0.2.9"},
        # no traffic block -> bytes_in / bytes_out are entirely null in this batch
    }
    with ParquetSink(_settings(tmp_path)) as sink:
        sink.write(_ne("d", "zeek_dns", dns))

    table = _read(_one_file(tmp_path / "silver"))
    assert str(table.schema.field("bytes_in").type) == "int64"
    assert table.column("bytes_in").to_pylist() == [None]
    assert table.column("dst_port").to_pylist() == [None]


def test_close_is_idempotent(tmp_path: Path) -> None:
    sink = ParquetSink(_settings(tmp_path))
    sink.write(_ne("e", "fortigate_traffic", _ocsf_4001(time_ns=_SEP_1)))
    assert len(sink.close()) == 1
    assert sink.close() == []
