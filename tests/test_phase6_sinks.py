"""Phase-6 end-to-end: the silver Parquet lake, DuckDB queries, compaction,
reprocessing from bronze, and DLQ replay once a new source definition lands.

* 10000 events through the full pipeline land in Parquet, correctly
  partitioned by ``date=`` / ``source_type=``.
* :class:`~ulpf.sinks.duckdb_query.LakeQuery` reads that same lake back and
  aggregates it per source correctly.
* :class:`~ulpf.sinks.compaction.Compactor` collapses many small files into
  few large ones, preserving every row exactly.
* ``ulpf reprocess`` against an *unchanged* source definition reproduces the
  original silver rows exactly (requirement d: traceability makes the
  comparison possible at all).
* a dead letter that no source understood replays successfully — and is
  marked resolved, not deleted — the moment its source YAML is added
  (requirement e: plug-and-play onboarding).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from ulpf.cli.dlq import run_replay
from ulpf.cli.reprocess import run_reprocess
from ulpf.config.settings import (
    EnrichSettings,
    ParseSettings,
    PipelineSettings,
    Settings,
    StorageSettings,
)
from ulpf.core.models import NormalizedEvent, RawEvent
from ulpf.core.pipeline import ParseStage, Pipeline, RawStoreStage
from ulpf.enrich.factory import build_enrichers
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.compaction import Compactor
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.duckdb_query import LakeQuery
from ulpf.sinks.manager import SinkManager
from ulpf.sinks.parquet_sink import ParquetSink
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent
_SEP_1_NS = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z


def _settings(root: Path, *, sources_dir: Path | None = None) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=root / "bronze",
            silver_path=root / "silver",
            dlq_path=root / "dlq",
            state_path=root / "state",
        ),
        parse=ParseSettings(sources_dir=sources_dir or _REPO / "configs" / "sources"),
        pipeline=PipelineSettings(worker_count=4),
        enrich=EnrichSettings(enabled=False),  # enrichment is exercised in test_phase4; not here
    )


def _fortigate_lines(n: int, *, date: str) -> list[bytes]:
    """Distinct synthetic FortiGate traffic lines, dated ``date`` (see test_phase5)."""
    return [
        (
            f"<189>date={date} time=10:{i // 60 % 60:02d}:{i % 60:02d} "
            f'devname="FGT" logid="0000000013" type="traffic" subtype="forward" '
            f'level="warning" srcip=192.0.2.{i % 254 + 1} srcport={10000 + i} '
            f"dstip=198.51.100.{i % 254 + 1} dstport=443 proto=6 "
            f'action="{"deny" if i % 7 == 0 else "accept"}" policyid=9 '
            f"sentbyte={i} rcvdbyte={2 * i}"
        ).encode()
        for i in range(n)
    ]


def _suricata_flow_lines(n: int, *, date: str) -> list[bytes]:
    """Distinct synthetic Suricata EVE ``flow`` records, dated ``date``."""
    lines = []
    for i in range(n):
        record = {
            "timestamp": f"{date}T10:{i // 60 % 60:02d}:{i % 60:02d}.000000+0000",
            "event_type": "flow",
            "src_ip": f"10.0.{i % 254}.5",
            "src_port": 20_000 + i,
            "dest_ip": f"10.1.{i % 254}.9",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": i,
            "flow": {
                "bytes_toserver": i,
                "bytes_toclient": 2 * i,
                "pkts_toserver": 1,
                "pkts_toclient": 1,
                "state": "established",
            },
        }
        lines.append(json.dumps(record).encode())
    return lines


def _build_pipeline(settings: Settings) -> tuple[Pipeline, SinkManager]:
    """The same stage chain :class:`~ulpf.core.runtime.Runtime` uses, minus integrity/listeners."""
    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)
    enrich = EnrichmentPipeline(settings, build_enrichers(settings))
    sinks = SinkManager.from_settings(settings)
    pipeline = Pipeline(
        settings,
        [
            RawStoreStage(RawStore(settings)),
            ParseStage(settings, ParseCoordinator()),
            NormalizeStage(settings, registry),
            EnrichStage(settings, enrich),
            ValidateStage(settings, registry),
            sinks,
        ],
    )
    return pipeline, sinks


async def _ingest(settings: Settings, lines: list[bytes]) -> list[RawEvent]:
    """Push ``lines`` through the full pipeline (as ``ulpf run`` would) and wait for it to drain."""
    events = [make_raw_event(line, source_id="phase6", transport="udp") for line in lines]
    pipeline, sinks = _build_pipeline(settings)
    await sinks.start()
    pipeline.start()
    for event in events:
        await pipeline.submit(event)
    await pipeline.stop()  # drains the queue, then flushes every sink
    return events


def _today_utc() -> str:
    """Today's UTC date - the bronze ingest partition every ``make_raw_event`` lands in."""
    return dt.datetime.now(dt.UTC).date().isoformat()


def _all_silver_rows(settings: Settings) -> list[dict]:
    silver = Path(settings.storage.silver_path)
    return [
        row
        for path in silver.rglob("part-*.parquet")
        for row in pq.ParquetFile(path).read().to_pylist()
    ]


# ======================================================================
# 1-2. 10000 events -> Parquet partitioning, then LakeQuery over the same lake
# ======================================================================


@pytest.fixture(scope="module")
def big_lake(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Ingest 10000 events (two sources, two dates) once; both tests below read it."""
    root = tmp_path_factory.mktemp("phase6-lake")
    settings = _settings(root)
    fg_lines = _fortigate_lines(6000, date="2026-09-01")
    suricata_lines = _suricata_flow_lines(4000, date="2026-09-02")
    asyncio.run(_ingest(settings, fg_lines + suricata_lines))
    return settings


def test_10000_events_land_in_parquet_with_correct_partitioning(big_lake: Settings) -> None:
    silver = Path(big_lake.storage.silver_path)
    fg_dir = silver / "date=2026-09-01" / "source_type=fortigate_traffic"
    suricata_dir = silver / "date=2026-09-02" / "source_type=suricata_eve_flow"
    assert fg_dir.is_dir() and suricata_dir.is_dir()
    # no other partitions exist - every event landed under one of these two
    assert {p.name for p in silver.glob("date=*")} == {"date=2026-09-01", "date=2026-09-02"}

    fg_rows = sum(pq.ParquetFile(p).metadata.num_rows for p in fg_dir.glob("part-*.parquet"))
    suricata_rows = sum(
        pq.ParquetFile(p).metadata.num_rows for p in suricata_dir.glob("part-*.parquet")
    )
    assert fg_rows == 6000
    assert suricata_rows == 4000

    all_rows = sum(pq.ParquetFile(p).metadata.num_rows for p in silver.rglob("part-*.parquet"))
    assert all_rows == 10_000

    # every event normalized and validated cleanly - nothing dead-lettered
    assert DeadLetterQueue(big_lake).stats()["total"] == 0


def test_lakequery_returns_them_and_aggregates_by_source_correctly(big_lake: Settings) -> None:
    with LakeQuery(big_lake) as lake:
        total = lake.query("SELECT COUNT(*) AS n FROM events")[0]["n"]
        assert total == 10_000

        dates = [
            row["date"] for row in lake.query("SELECT DISTINCT date FROM events ORDER BY date")
        ]
        assert dates == ["2026-09-01", "2026-09-02"]

        by_source = {row["source_type"]: row for row in lake.stats_by_source()}
        assert set(by_source) == {"fortigate_traffic", "suricata_eve_flow"}

        fg = by_source["fortigate_traffic"]
        assert fg["events"] == 6000
        assert fg["distinct_src_ip"] == 254  # srcip cycles through 192.0.2.1-254
        assert fg["total_bytes"] == sum(3 * i for i in range(6000))  # sentbyte + rcvdbyte

        suricata = by_source["suricata_eve_flow"]
        assert suricata["events"] == 4000
        assert suricata["distinct_src_ip"] == 254
        assert suricata["total_bytes"] == sum(
            3 * i for i in range(4000)
        )  # bytes_toserver + toclient

        # by_source() output is queryable as ordinary events too
        sample = lake.by_source("fortigate_traffic", limit=5)
        assert len(sample) == 5
        assert all(row["source_type"] == "fortigate_traffic" for row in sample)


# ======================================================================
# 3. compaction reduces file count, preserves the row count exactly
# ======================================================================


def _ocsf_4001(*, time_ns: int, src: str) -> dict[str, object]:
    return {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "type_uid": 400106,
        "severity_id": 1,
        "time": time_ns,
        "src_endpoint": {"ip": src, "port": 51000},
        "dst_endpoint": {"ip": "198.51.100.5", "port": 443},
        "connection_info": {"protocol_name": "tcp", "protocol_num": 6},
        "traffic": {"bytes_in": 100, "bytes_out": 50},
        "action_id": 1,
    }


def _ne(uid: str, ocsf: dict[str, object]) -> NormalizedEvent:
    return NormalizedEvent(
        event_uid=uid,
        raw_hash="a" * 64,
        ingest_time_ns=ocsf["time"],  # type: ignore[arg-type]
        ocsf=ocsf,
        source_type="fortigate_traffic",
        mapping_version="1.0.0",
        enrichment={},
    )


def test_compaction_reduces_file_count_and_preserves_row_count_exactly(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    sink = ParquetSink(settings, max_rows=50)  # small -> many part files
    uids = [f"evt-{i:05d}" for i in range(2000)]
    for i, uid in enumerate(uids):
        sink.write(_ne(uid, _ocsf_4001(time_ns=_SEP_1_NS + i, src=f"192.0.2.{i % 254 + 1}")))
    sink.close()

    part_dir = (
        Path(settings.storage.silver_path) / "date=2026-09-01" / "source_type=fortigate_traffic"
    )
    files_before = list(part_dir.glob("part-*.parquet"))
    assert len(files_before) == 40  # 2000 / 50
    uids_before = {
        uid
        for path in files_before
        for uid in pq.ParquetFile(path).read().column("event_uid").to_pylist()
    }
    assert uids_before == set(uids)

    result = Compactor(settings).compact("2026-09-01", "fortigate_traffic")

    assert result.compacted is True
    assert result.files_before == 40
    assert result.files_after < result.files_before
    assert result.rows == 2000

    files_after = list(part_dir.glob("part-*.parquet"))
    assert len(files_after) == result.files_after
    rows_after = sum(pq.ParquetFile(p).metadata.num_rows for p in files_after)
    assert rows_after == 2000  # not one row lost or duplicated
    uids_after = {
        uid
        for path in files_after
        for uid in pq.ParquetFile(path).read().column("event_uid").to_pylist()
    }
    assert uids_after == uids_before  # same events, just fewer files


# ======================================================================
# 4. reprocess from bronze reproduces identical output for an unchanged mapping
# ======================================================================


def test_reprocess_with_an_unchanged_mapping_reproduces_identical_output(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    # `ulpf reprocess --date` scopes the BRONZE (ingest-date) partition, which is
    # always "now" (raw evidence has no other notion of when it arrived), and
    # `--compare` looks up the PREVIOUS silver rows under that same date - so the
    # log's own `date=` field (which drives the silver partition) must match too.
    today = _today_utc()
    asyncio.run(_ingest(settings, _fortigate_lines(500, date=today)))
    original_rows = {row["event_uid"]: row for row in _all_silver_rows(settings)}
    assert len(original_rows) == 500

    report = asyncio.run(
        run_reprocess(
            settings, date=today, source_type="fortigate_traffic", dry_run=False, compare=True
        )
    )

    assert report.normalized == 500
    assert report.written == 500
    compare = report.compare
    assert compare is not None
    assert compare.no_previous == 0
    assert compare.changed == 0
    assert compare.unchanged == 500
    assert compare.delta_avg == pytest.approx(0.0, abs=1e-9)

    # reprocessing keeps the SAME event_uid (requirement d) - it never overwrites
    # the original; both generations now coexist, distinguishable only by the
    # new run's `metadata.log_version` tag (nothing else in the row differs).
    by_uid: dict[str, list[dict]] = {}
    for row in _all_silver_rows(settings):
        by_uid.setdefault(row["event_uid"], []).append(row)
    assert len(by_uid) == 500
    assert all(len(rows) == 2 for rows in by_uid.values())

    for uid, rows in by_uid.items():
        original = next(r for r in rows if not r.get("metadata.log_version"))
        reprocessed = next(r for r in rows if r.get("metadata.log_version"))
        assert reprocessed["src_ip"] == original["src_ip"]
        assert reprocessed["dst_ip"] == original["dst_ip"]
        assert reprocessed["time"] == original["time"]
        assert reprocessed["bytes_in"] == original["bytes_in"]
        assert reprocessed["bytes_out"] == original["bytes_out"]
        assert reprocessed["raw_hash"] == original["raw_hash"] == original_rows[uid]["raw_hash"]


# ======================================================================
# 5. a DLQ entry replays successfully once its source YAML is added
# ======================================================================


_ACME_LINE = json.dumps(
    {
        "vendor": "ACMEFW",
        "ts": "2026-09-05T10:00:00Z",
        "src_ip": "203.0.113.5",
        "src_port": 51000,
        "dst_ip": "198.51.100.9",
        "dst_port": 443,
        "proto": "tcp",
        "action": "deny",
    }
).encode()

_ACME_SOURCE_YAML = """
name: acme_fw
version: "1.0.0"
vendor: Acme
product: Acme Firewall
product_version: "1.0"
priority: 50

detect:
  all:
    - contains: '"vendor": "ACMEFW"'
    - field_equals: {name: vendor, value: ACMEFW}

parse:
  envelope: none
  engine: json
  options: {}

normalize:
  class_uid: 4001
  category_uid: 4
  activity_id: 6
  constants:
    metadata.product.vendor_name: Acme
    metadata.product.name: Acme Firewall
    severity_id: 1
  fields:
    src_endpoint.ip: {from: src_ip, type: ip, required: true}
    src_endpoint.port: {from: src_port, type: int}
    dst_endpoint.ip: {from: dst_ip, type: ip, required: true}
    dst_endpoint.port: {from: dst_port, type: int}
    connection_info.protocol_name: {from: proto, type: str}
    action_id: {from: action, map: {deny: 2, allow: 1}, default: 0}
    action: {from: action, map: {deny: Denied, allow: Allowed}, default: null}
    time: {from: ts, type: timestamp, required: true}
  unmapped: keep_all

validate:
  required: [src_endpoint.ip, dst_endpoint.ip, time, class_uid, category_uid]
  on_failure: dead_letter
"""


def test_dlq_entry_replays_successfully_after_a_new_source_yaml_is_added(tmp_path: Path) -> None:
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir()
    settings = _settings(tmp_path, sources_dir=sources_dir)

    # seed: the raw event sits safely in bronze, but no source YAML understands
    # it yet, so it was dead-lettered (exactly what would happen were this run
    # through the real pipeline against today's - empty - source set).
    store = RawStore(settings)
    event = make_raw_event(_ACME_LINE, source_id="phase6", transport="udp")
    store.write(event)
    store.flush()
    dlq = DeadLetterQueue(settings)
    dlq.write(event, reason="unsniffable", stage="detect", detail={"note": "no source YAML yet"})
    assert dlq.stats() == {
        "total": 1,
        "resolved": 0,
        "unresolved": 1,
        "by_reason": {"unsniffable": 1},
        "by_stage": {"detect": 1},
    }

    # fix: onboard the vendor - one new YAML file, no code, no restart (requirement e)
    (sources_dir / "acme_fw.yaml").write_text(_ACME_SOURCE_YAML, encoding="utf-8")

    report = asyncio.run(run_replay(settings, reason=None, since=None, dry_run=False))

    assert report.candidates == 1
    assert report.succeeded == 1
    assert report.still_failing == 0
    assert report.written == 1

    # resolved, never deleted - the original failure stays in the audit trail
    assert dlq.resolved_event_uids() == {event.event_uid}
    stats = dlq.stats()
    assert stats["total"] == 1 and stats["resolved"] == 1 and stats["unresolved"] == 0

    rows = _all_silver_rows(settings)
    assert len(rows) == 1
    assert rows[0]["event_uid"] == event.event_uid
    assert rows[0]["raw_hash"] == event.raw_hash  # requirement d: traceability preserved
    assert rows[0]["source_type"] == "acme_fw"
    assert rows[0]["src_ip"] == "203.0.113.5"
    assert rows[0]["dst_ip"] == "198.51.100.9"
