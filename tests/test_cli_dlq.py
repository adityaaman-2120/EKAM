"""Tests for :mod:`ulpf.cli.dlq` — ``ulpf dlq stats/sample/replay``."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from ulpf.cli import dlq as dlq_mod
from ulpf.cli.main import app
from ulpf.config.settings import ParseSettings, Settings, StorageSettings
from ulpf.core.models import DeadLetter, RawEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

runner = CliRunner()
_REPO = Path(__file__).resolve().parent.parent
_TODAY = dt.datetime.now(dt.UTC).date().isoformat()

# Detected and normalized cleanly by configs/sources/fortigate_traffic.yaml -
# stands in for "a dead letter that now replays successfully" (e.g. after a
# source YAML fix): it is seeded straight into the DLQ under a fabricated
# reason, as if an older/broken definition had rejected it.
_GOOD_LINE = (
    f'<189>date={_TODAY} time=22:14:05 devname="FGT" logid="0000000013" '
    'type="traffic" subtype="forward" srcip=10.0.0.9 srcport=51000 '
    'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=100 rcvdbyte=200'
).encode()

# date/time cannot be parsed -> mapping fails again on replay, every time.
_BAD_LINE = (
    b'<189>date=not-a-date time=not-a-time devname="FGT" logid="0000000013" '
    b'type="traffic" subtype="forward" srcip=10.0.0.10 srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0'
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            state_path=tmp_path / "state",
        ),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
    )


def _seed_dlq_entry(
    settings: Settings, raw: bytes, *, reason: str, stage: str
) -> tuple[RawEvent, DeadLetter]:
    """Put ``raw`` in bronze (as evidence) and directly write a dead-letter for it."""
    store = RawStore(settings)
    event = make_raw_event(raw, source_id="t", transport="udp")
    store.write(event)
    store.flush()
    entry = DeadLetterQueue(settings).write(
        event, reason=reason, stage=stage, detail={"note": "seeded for test"}
    )
    return event, entry


@pytest.fixture
def wired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = _settings(tmp_path)
    monkeypatch.setattr(dlq_mod, "_load_settings", lambda: settings)
    return settings


def _silver_rows(settings: Settings) -> list[dict]:
    silver = Path(settings.storage.silver_path)
    return [
        row
        for path in silver.rglob("part-*.parquet")
        for row in pq.ParquetFile(path).read().to_pylist()
    ]


# --------------------------------------------------------------------------
# dlq stats


def test_stats_counts_by_reason_and_stage(wired: Settings) -> None:
    _seed_dlq_entry(wired, _GOOD_LINE, reason="mapping_error", stage="normalize")
    _seed_dlq_entry(wired, _GOOD_LINE, reason="mapping_error", stage="normalize")
    _seed_dlq_entry(wired, _BAD_LINE, reason="unsniffable", stage="detect")

    result = runner.invoke(app, ["dlq", "stats", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["total"] == 3
    assert body["resolved"] == 0
    assert body["unresolved"] == 3
    assert body["by_reason"] == {"mapping_error": 2, "unsniffable": 1}
    assert body["by_stage"] == {"normalize": 2, "detect": 1}


def test_stats_rich_output_shows_totals_and_tables(wired: Settings) -> None:
    _seed_dlq_entry(wired, _GOOD_LINE, reason="mapping_error", stage="normalize")

    result = runner.invoke(app, ["dlq", "stats"])
    assert result.exit_code == 0, result.stdout
    assert "dlq stats" in result.stdout
    assert "mapping_error" in result.stdout
    assert "normalize" in result.stdout


def test_stats_on_an_empty_queue_is_a_clean_zero(wired: Settings) -> None:
    result = runner.invoke(app, ["dlq", "stats", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["total"] == 0 and body["by_reason"] == {} and body["by_stage"] == {}


# --------------------------------------------------------------------------
# dlq sample


def test_sample_prints_raw_lines_for_one_reason(wired: Settings) -> None:
    _, first = _seed_dlq_entry(wired, _GOOD_LINE, reason="target_reason", stage="normalize")
    _, second = _seed_dlq_entry(wired, _BAD_LINE, reason="target_reason", stage="normalize")
    _seed_dlq_entry(wired, _GOOD_LINE, reason="other_reason", stage="detect")

    result = runner.invoke(app, ["dlq", "sample", "--reason", "target_reason", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert [row["event_uid"] for row in body] == [first.event_uid, second.event_uid]
    assert body[0]["raw"] == _GOOD_LINE.decode()
    assert body[1]["raw"] == _BAD_LINE.decode()
    assert all(row["reason"] == "target_reason" for row in body)


def test_sample_respects_the_count_limit(wired: Settings) -> None:
    for _ in range(5):
        _seed_dlq_entry(wired, _GOOD_LINE, reason="target_reason", stage="normalize")

    result = runner.invoke(app, ["dlq", "sample", "--reason", "target_reason", "-n", "2", "--json"])
    assert result.exit_code == 0, result.stdout
    assert len(json.loads(result.stdout)) == 2


def test_sample_with_no_matching_reason_reports_none(wired: Settings) -> None:
    result = runner.invoke(app, ["dlq", "sample", "--reason", "no_such_reason"])
    assert result.exit_code == 0, result.stdout
    assert "no dead letters" in result.stdout


# --------------------------------------------------------------------------
# dlq replay


def test_replay_dry_run_previews_without_writing_or_resolving(wired: Settings) -> None:
    _, entry = _seed_dlq_entry(wired, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    result = runner.invoke(app, ["dlq", "replay", "--dry-run", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["dry_run"] is True
    assert body["candidates"] == 1
    assert body["succeeded"] == 1
    assert body["still_failing"] == 0
    assert body["written"] == 0  # never attempted, dry run

    assert DeadLetterQueue(wired).resolved_event_uids() == set()
    assert _silver_rows(wired) == []
    # nothing marked resolved -> the entry is still a replay candidate
    assert [e.event_uid for e in DeadLetterQueue(wired).iter_entries(unresolved_only=True)] == [
        entry.event_uid
    ]


def test_replay_success_marks_resolved_and_writes_to_sinks(wired: Settings) -> None:
    event, entry = _seed_dlq_entry(wired, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    result = runner.invoke(app, ["dlq", "replay", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["candidates"] == 1
    assert body["succeeded"] == 1
    assert body["written"] == 1

    dlq = DeadLetterQueue(wired)
    assert dlq.resolved_event_uids() == {entry.event_uid}
    stats = dlq.stats()
    assert stats["total"] == 1 and stats["resolved"] == 1 and stats["unresolved"] == 0

    rows = _silver_rows(wired)
    assert len(rows) == 1
    assert rows[0]["event_uid"] == event.event_uid
    assert rows[0]["source_type"] == "fortigate_traffic"


def test_replay_still_failing_entry_stays_unresolved_and_relogs(wired: Settings) -> None:
    _, entry = _seed_dlq_entry(wired, _BAD_LINE, reason="seeded_broken", stage="parse")

    result = runner.invoke(app, ["dlq", "replay", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["candidates"] == 1
    assert body["succeeded"] == 0
    assert body["still_failing"] == 1

    dlq = DeadLetterQueue(wired)
    assert entry.event_uid not in dlq.resolved_event_uids()
    # the pipeline dead-lettered it again -> a second, independent entry
    assert dlq.stats()["total"] == 2
    assert _silver_rows(wired) == []


def test_replay_reason_filter_only_touches_matching_entries(wired: Settings) -> None:
    _, fixable = _seed_dlq_entry(wired, _GOOD_LINE, reason="fixed_reason", stage="normalize")
    _, other = _seed_dlq_entry(wired, _GOOD_LINE, reason="other_reason", stage="normalize")

    result = runner.invoke(app, ["dlq", "replay", "--reason", "fixed_reason", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["candidates"] == 1 and body["succeeded"] == 1

    resolved = DeadLetterQueue(wired).resolved_event_uids()
    assert resolved == {fixable.event_uid}
    assert other.event_uid not in resolved


def test_replay_since_filter_excludes_older_entries(wired: Settings) -> None:
    _seed_dlq_entry(wired, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    future = (dt.datetime.now(dt.UTC) + dt.timedelta(days=1)).date().isoformat()
    excluded = runner.invoke(app, ["dlq", "replay", "--since", future, "--json"])
    assert json.loads(excluded.stdout)["candidates"] == 0

    past = (dt.datetime.now(dt.UTC) - dt.timedelta(days=1)).date().isoformat()
    included = runner.invoke(app, ["dlq", "replay", "--since", past, "--json"])
    assert json.loads(included.stdout)["candidates"] == 1


def test_replay_rich_output_reports_scope_and_counts(wired: Settings) -> None:
    _seed_dlq_entry(wired, _GOOD_LINE, reason="old_parser_bug", stage="normalize")

    result = runner.invoke(app, ["dlq", "replay", "--reason", "old_parser_bug"])
    assert result.exit_code == 0, result.stdout
    assert "old_parser_bug" in result.stdout
    assert "dlq replay" in result.stdout


def test_replay_on_an_empty_queue_is_a_clean_no_op(wired: Settings) -> None:
    result = runner.invoke(app, ["dlq", "replay", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body == {
        "reason": None,
        "since": None,
        "dry_run": False,
        "candidates": 0,
        "succeeded": 0,
        "still_failing": 0,
        "written": 0,
    }
