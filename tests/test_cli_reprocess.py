"""Tests for :mod:`ulpf.cli.reprocess` — ``ulpf reprocess`` and its ``--compare`` mode."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from ulpf.cli import reprocess as reprocess_mod
from ulpf.cli.main import app
from ulpf.config.settings import ParseSettings, Settings, StorageSettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

runner = CliRunner()
_REPO = Path(__file__).resolve().parent.parent
_TODAY = dt.datetime.now(dt.UTC).date().isoformat()

# The FortiGate detector matches on content, not on date; the OCSF `time` field
# (and therefore the silver partition date) comes from the log's own
# date=/time= fields, so it is stamped with _TODAY to line up with the bronze
# ingest-date partition (which is always "now").
_GOOD_LINES = [
    (
        f'<189>date={_TODAY} time=22:14:{i:02d} devname="FGT" logid="0000000013" '
        f'type="traffic" subtype="forward" srcip=10.0.0.{i} srcport=51000 '
        f'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=100 rcvdbyte=200'
    ).encode()
    for i in range(5)
]
# date/time cannot be parsed -> the required `time` mapping raises -> dead-lettered
_BAD_LINE = (
    b'<189>date=not-a-date time=not-a-time devname="FGT" logid="0000000013" '
    b'type="traffic" subtype="forward" srcip=10.0.0.9 srcport=51000 '
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


def _seed_bronze(settings: Settings, lines: list[bytes]) -> None:
    store = RawStore(settings)
    for line in lines:
        store.write(make_raw_event(line, source_id="t", transport="udp"))
    store.flush()


@pytest.fixture
def populated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = _settings(tmp_path)
    _seed_bronze(settings, _GOOD_LINES)
    monkeypatch.setattr(reprocess_mod, "_load_settings", lambda: settings)
    return settings


def _silver_rows(settings: Settings, date: str, source_type: str) -> list[dict]:
    part_dir = Path(settings.storage.silver_path) / f"date={date}" / f"source_type={source_type}"
    rows: list[dict] = []
    for path in sorted(part_dir.glob("part-*.parquet")):
        rows.extend(pq.ParquetFile(path).read().to_pylist())
    return rows


# --------------------------------------------------------------------------
# basic run


def test_reprocess_writes_silver_and_reports_counts(populated: Settings) -> None:
    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["raw_events"] == 5
    assert body["in_scope"] == 5
    assert body["normalized"] == 5
    assert body["dead_lettered"] == 0
    assert body["written"] == 5
    assert body["mapping_version_tag"].startswith("reprocess-")
    assert body["dry_run"] is False
    assert body["compare"] is None

    rows = _silver_rows(populated, _TODAY, "fortigate_traffic")
    assert len(rows) == 5
    expected_tag = f"1.0.0+{body['mapping_version_tag']}"
    assert all(row["metadata.log_version"] == expected_tag for row in rows)


def test_reprocess_source_type_filter_excludes_non_matching_events(populated: Settings) -> None:
    result = runner.invoke(
        app, ["reprocess", "--date", _TODAY, "--source-type", "no_such_source", "--json"]
    )
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["raw_events"] == 5
    assert body["in_scope"] == 0
    assert body["normalized"] == 0
    assert body["written"] == 0


def test_reprocess_unknown_date_is_a_clean_no_op(populated: Settings) -> None:
    result = runner.invoke(app, ["reprocess", "--date", "2020-01-01", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)
    assert body["raw_events"] == 0
    assert body["normalized"] == 0
    assert body["written"] == 0


def test_reprocess_rich_output_mentions_date_and_scope(populated: Settings) -> None:
    result = runner.invoke(app, ["reprocess", "--date", _TODAY])
    assert result.exit_code == 0, result.stdout
    assert _TODAY in result.stdout
    assert "reprocess" in result.stdout


# --------------------------------------------------------------------------
# bronze ingest date vs. silver event date


def test_reprocess_writes_to_silver_under_the_event_date_not_the_bronze_date(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bronze partitions by ingest date (always "today" here); FortiGate's own

    ``date=`` field can say something else entirely. The corrected row must
    land in silver under THAT event date, never under the bronze ingest date.
    """
    settings = _settings(tmp_path)
    event_date = "2026-08-20"
    assert event_date != _TODAY
    line = (
        f'<189>date={event_date} time=22:14:00 devname="FGT" logid="0000000013" '
        f'type="traffic" subtype="forward" srcip=10.0.0.1 srcport=51000 '
        f'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=100 rcvdbyte=200'
    ).encode()
    _seed_bronze(settings, [line])  # ingest_time_ns is "now" -> bronze lands under date=_TODAY
    monkeypatch.setattr(reprocess_mod, "_load_settings", lambda: settings)

    assert (Path(settings.storage.bronze_path) / f"date={_TODAY}").is_dir()

    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["date"] == _TODAY  # the bronze ingest date that was read
    assert body["silver_dates"] == [event_date]  # the event date silver was written under

    assert len(_silver_rows(settings, event_date, "fortigate_traffic")) == 1
    assert _silver_rows(settings, _TODAY, "fortigate_traffic") == []  # nothing under ingest date


def test_reprocess_rich_output_prints_both_bronze_and_silver_dates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    event_date = "2026-08-20"
    line = (
        f'<189>date={event_date} time=22:14:00 devname="FGT" logid="0000000013" '
        f'type="traffic" subtype="forward" srcip=10.0.0.1 srcport=51000 '
        f'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=100 rcvdbyte=200'
    ).encode()
    _seed_bronze(settings, [line])
    monkeypatch.setattr(reprocess_mod, "_load_settings", lambda: settings)

    result = runner.invoke(app, ["reprocess", "--date", _TODAY])
    assert result.exit_code == 0, result.stdout
    assert f"bronze date={_TODAY}" in result.stdout
    assert f"silver dates={event_date}" in result.stdout


# --------------------------------------------------------------------------
# --dry-run


def test_dry_run_writes_no_silver_files_but_reports_accurate_counts(populated: Settings) -> None:
    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--dry-run", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["dry_run"] is True
    assert body["raw_events"] == 5
    assert body["in_scope"] == 5
    assert body["normalized"] == 5
    assert body["written"] == 0  # never attempted, dry run

    silver = Path(populated.storage.silver_path)
    assert not silver.exists() or not any(silver.rglob("*.parquet"))


def test_dry_run_dead_letters_go_to_an_isolated_dlq_not_the_real_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _seed_bronze(settings, [*_GOOD_LINES, _BAD_LINE])
    monkeypatch.setattr(reprocess_mod, "_load_settings", lambda: settings)

    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--dry-run", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["raw_events"] == 6
    assert body["dead_lettered"] == 1
    # the real DLQ configured in settings must stay untouched
    assert DeadLetterQueue(settings).stats()["total"] == 0


def test_real_run_dead_letters_land_in_the_real_dlq(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _seed_bronze(settings, [*_GOOD_LINES, _BAD_LINE])
    monkeypatch.setattr(reprocess_mod, "_load_settings", lambda: settings)

    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    assert body["dead_lettered"] == 1
    assert DeadLetterQueue(settings).stats()["total"] == 1


# --------------------------------------------------------------------------
# --compare


def test_compare_on_first_ever_run_reports_no_previous(populated: Settings) -> None:
    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--compare", "--json"])
    assert result.exit_code == 0, result.stdout
    body = json.loads(result.stdout)

    compare = body["compare"]
    assert compare["no_previous"] == 5
    assert compare["changed"] == 0
    assert compare["unchanged"] == 0
    assert compare["completeness_old_avg"] is None
    assert compare["completeness_new_avg"] is None
    assert compare["completeness_delta_avg"] is None


def test_compare_on_a_second_identical_run_reports_unchanged_and_stable_completeness(
    populated: Settings,
) -> None:
    first = runner.invoke(app, ["reprocess", "--date", _TODAY, "--json"])
    assert first.exit_code == 0, first.stdout

    second = runner.invoke(app, ["reprocess", "--date", _TODAY, "--compare", "--json"])
    assert second.exit_code == 0, second.stdout
    body = json.loads(second.stdout)

    compare = body["compare"]
    assert compare["no_previous"] == 0
    assert compare["changed"] == 0
    assert compare["unchanged"] == 5
    assert compare["completeness_old_avg"] == pytest.approx(compare["completeness_new_avg"])
    assert compare["completeness_delta_avg"] == pytest.approx(0.0)

    # both generations coexist, distinguishable by mapping_version tag
    first_tag = f"1.0.0+{json.loads(first.stdout)['mapping_version_tag']}"
    second_tag = f"1.0.0+{body['mapping_version_tag']}"
    assert first_tag != second_tag
    rows = _silver_rows(populated, _TODAY, "fortigate_traffic")
    assert len(rows) == 10
    assert {row["metadata.log_version"] for row in rows} == {first_tag, second_tag}


def test_compare_rich_output_shows_the_compare_table(populated: Settings) -> None:
    runner.invoke(app, ["reprocess", "--date", _TODAY])
    result = runner.invoke(app, ["reprocess", "--date", _TODAY, "--compare"])
    assert result.exit_code == 0, result.stdout
    assert "compare vs. previous mapping_version" in result.stdout
