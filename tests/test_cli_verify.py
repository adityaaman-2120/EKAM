"""Tests for :mod:`ulpf.cli.verify` — the ``ulpf verify`` demo command."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ulpf.cli import verify as verify_mod
from ulpf.cli.main import app
from ulpf.config.settings import (
    IntegritySettings,
    ParseSettings,
    Settings,
    StorageSettings,
)
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.sinks.raw_store import RawStore

runner = CliRunner()
_REPO = Path(__file__).resolve().parent.parent

_FORTI_LINES = [
    b'<189>date=2026-08-15 time=22:14:%02d level="warning" devname="FGT" '
    b'logid="0000000013" type="traffic" subtype="forward" srcip=10.0.0.%d srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0' % (i, i)
    for i in range(5)
]


def _settings(tmp_path: Path) -> Settings:
    keys = generate_keypair(tmp_path / "keys")
    return Settings(
        storage=StorageSettings(bronze_path=tmp_path / "bronze", ledger_path=tmp_path / "ledger"),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
        integrity=IntegritySettings(signing_key_path=keys.private, public_key_path=keys.public),
    )


def _seal_one_batch(settings: Settings, lines: list[bytes]):  # noqa: ANN202
    store = RawStore(settings)
    events = [make_raw_event(line, source_id="t", transport="udp") for line in lines]
    for event in events:
        store.write(event)
    store.flush()
    signer = Signer.load(settings.integrity.signing_key_path)
    ledger = IntegrityLedger(settings, signer)
    index = IntegrityIndex(Path(settings.storage.ledger_path) / "event_index.sqlite")
    uids = [e.event_uid for e in events]
    entry = ledger.append_batch([bytes.fromhex(e.raw_hash) for e in events], event_uids=uids)
    index.add_batch(entry.seq, uids)
    index.close()
    return events


@pytest.fixture
def populated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    settings = _settings(tmp_path)
    events = _seal_one_batch(settings, _FORTI_LINES)
    monkeypatch.setattr(verify_mod, "_load_settings", lambda: settings)
    return settings, events


def _tamper_bronze(settings: Settings, event_uid: str) -> None:
    path = next(Path(settings.storage.bronze_path).rglob("events.ndjson.gz"))
    with gzip.open(path, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == event_uid:
            record["raw_b64"] = base64.b64encode(b"attacker rewrote this").decode("ascii")
    with gzip.open(path, "wb") as handle:
        for record in records:
            handle.write((json.dumps(record, separators=(",", ":")) + "\n").encode())


def _corrupt_ledger_line(settings: Settings, index: int) -> None:
    path = Path(settings.storage.ledger_path) / LEDGER_FILENAME
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[index])
    row["batch_root"] = "ff" * 32
    lines[index] = json.dumps(row, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# verify chain


def test_verify_chain_reports_an_intact_ledger(populated) -> None:  # noqa: ANN001
    result = runner.invoke(app, ["verify", "chain", "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["ok"] is True and body["broken_at"] is None
    assert body["entries_total"] == 1 and body["checked"] == 1


def test_verify_chain_names_the_broken_sequence_number(populated) -> None:  # noqa: ANN001
    settings, _events = populated
    _corrupt_ledger_line(settings, 0)

    result = runner.invoke(app, ["verify", "chain"])
    assert result.exit_code == 1
    assert "CHAIN BROKEN AT SEQ 0" in result.stdout

    body = json.loads(runner.invoke(app, ["verify", "chain", "--json"]).stdout)
    assert body["ok"] is False and body["broken_at"] == 0
    assert body["broken_reason"]


def test_verify_chain_with_no_ledger_is_a_clean_no_op(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    settings = _settings(tmp_path)  # bronze/ledger dirs never written
    monkeypatch.setattr(verify_mod, "_load_settings", lambda: settings)
    result = runner.invoke(app, ["verify", "chain", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["ledger_present"] is False


# --------------------------------------------------------------------------
# verify events


def test_verify_events_passes_for_an_untouched_store(populated) -> None:  # noqa: ANN001
    _settings_, events = populated
    result = runner.invoke(app, ["verify", "events", "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["checked"] == len(events)
    assert body["passed"] == len(events) and body["failed"] == 0


def test_verify_events_flags_a_tampered_event_with_uid_and_locator(populated) -> None:  # noqa: ANN001
    settings, events = populated
    victim = events[2].event_uid
    _tamper_bronze(settings, victim)

    result = runner.invoke(app, ["verify", "events"])
    assert result.exit_code == 1
    assert "EVENT(S) FAILED" in result.stdout

    body = json.loads(runner.invoke(app, ["verify", "events", "--json"]).stdout)
    assert body["failed"] == 1 and body["passed"] == len(events) - 1
    failure = body["failures"][0]
    assert failure["event_uid"] == victim
    assert "#L" in failure["locator"]
    assert failure["hash_ok"] is False and failure["proof_ok"] is False
    assert "tamper" in failure["reason"].lower()


# --------------------------------------------------------------------------
# verify event <uid>


def test_verify_event_shows_the_merkle_path_for_a_good_event(populated) -> None:  # noqa: ANN001
    _settings_, events = populated
    result = runner.invoke(app, ["verify", "event", events[1].event_uid, "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["ok"] is True
    assert body["recorded_hash"] == body["recomputed_hash"]
    assert len(body["merkle_path"]) == 3  # ceil(log2(5))
    assert all(step["side"] in {"left", "right"} for step in body["merkle_path"])


def test_verify_event_fails_for_a_tampered_event(populated) -> None:  # noqa: ANN001
    settings, events = populated
    _tamper_bronze(settings, events[0].event_uid)
    result = runner.invoke(app, ["verify", "event", events[0].event_uid, "--json"])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["ok"] is False and body["hash_ok"] is False


# --------------------------------------------------------------------------
# verify roundtrip — requirement (a)


def test_verify_roundtrip_is_100_percent_for_an_untouched_store(populated) -> None:  # noqa: ANN001
    _settings_, events = populated
    result = runner.invoke(app, ["verify", "roundtrip"])
    assert result.exit_code == 0
    assert "REQUIREMENT (a): SATISFIED" in result.stdout

    body = json.loads(runner.invoke(app, ["verify", "roundtrip", "--json"]).stdout)
    assert body["total"] == len(events)
    assert body["requirement_a_satisfied"] is True
    assert body["byte_lossless"] == body["total"] and body["byte_lossless_rate"] == 100.0
    assert body["reparse_stable_rate"] == 100.0
    assert body["renormalize_stable_rate"] == 100.0
    assert body["dead_letter_count"] == 0


def test_verify_roundtrip_detects_storage_tampering(populated) -> None:  # noqa: ANN001
    settings, events = populated
    _tamper_bronze(settings, events[3].event_uid)

    result = runner.invoke(app, ["verify", "roundtrip", "--json"])
    assert result.exit_code == 1
    body = json.loads(result.stdout)
    assert body["requirement_a_satisfied"] is False
    assert body["byte_lossless"] == body["total"] - 1
    assert body["byte_lossless_rate"] < 100.0
    failure = body["failures"][0]
    assert failure["event_uid"] == events[3].event_uid
    assert failure["category"] == "byte"
    assert "altered in storage" in failure["reason"]


_GOOD_FORTI = (
    b'<189>date=2026-08-15 time=22:14:15 devname="FGT" logid="0000000013" '
    b'type="traffic" subtype="forward" srcip=10.0.0.%d srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0'
)
# same source (matches fortigate detect) but date/time cannot be parsed as a
# timestamp -> the required `time` mapping raises MappingError -> dead-lettered.
_BAD_FORTI = (
    b'<189>date=not-a-date time=not-a-time devname="FGT" logid="0000000013" '
    b'type="traffic" subtype="forward" srcip=10.0.0.%d srcport=51000 '
    b'dstip=8.8.8.8 dstport=443 proto=6 action="deny" policyid=9 sentbyte=0 rcvdbyte=0'
)


def test_verify_roundtrip_separates_evidence_loss_from_normalization_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every raw hash is intact; half the events fail normalization.

    Requirement (a) is byte-level -> SATISFIED at 100%. The normalization gap is
    reported separately as dead_letter_count, never dragging (a) down.
    """
    settings = _settings(tmp_path)
    monkeypatch.setattr(verify_mod, "_load_settings", lambda: settings)
    store = RawStore(settings)
    for i in range(6):
        store.write(make_raw_event(_GOOD_FORTI % i, source_id="t", transport="udp"))
        store.write(make_raw_event(_BAD_FORTI % i, source_id="t", transport="udp"))
    store.flush()

    result = runner.invoke(app, ["verify", "roundtrip"])
    assert "REQUIREMENT (a): SATISFIED" in result.stdout

    body = json.loads(runner.invoke(app, ["verify", "roundtrip", "--json"]).stdout)
    assert body["total"] == 12
    assert body["requirement_a_satisfied"] is True
    assert body["byte_lossless"] == 12 and body["byte_lossless_rate"] == 100.0
    assert body["reparse_stable"] == 12 and body["reparse_stable_rate"] == 100.0
    # the normalization gap is shown ONLY here — not folded into requirement (a)
    assert body["dead_letter_count"] == 6
    assert body["normalized_originally"] == 6
    assert body["renormalize_stable"] == 6 and body["renormalize_stable_rate"] == 100.0
    # no byte/reparse/renormalize failures — dead-letters are counted, not "failed"
    assert body["failures"] == []


# --------------------------------------------------------------------------
# reparse-stable must use the definition-driven path, not the sniff-only one

_PANOS_TRAFFIC_V10 = (
    b"<14>1 2026-09-01T12:00:03Z pa-fw1 - - - - "
    b"1,2026/09/01 12:00:03,001801234567,TRAFFIC,end,2622,2026/09/01 12:00:00,"
    b"192.0.2.15,203.0.113.9,198.51.100.7,203.0.113.9,allow-web,,,ssl,vsys1,trust,"
    b"untrust,ethernet1/2,ethernet1/1,forward-all,,104512,1,51234,443,51235,443,"
    b"0x400053,tcp,allow,5060,1240,3820,12,2026/09/01 11:59:48,12,"
    b"web-advertisements,0,7000000123,0x0,192.0.2.0-192.0.2.255,United States,0,7,5,"
    b"tcp-fin"
)


def test_verify_roundtrip_reparse_stable_is_100_percent_for_panos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BUG: PAN-OS TRAFFIC sniffs as "csv"; the sniff-only pass has no columns for

    it and used to raise on every single event, reporting a perfectly healthy,
    deterministic source as parser non-determinism (491/513 = 95.71% in one
    real run). reparse-stable must reparse with the MATCHED definition's own
    engine and options (its version-keyed column_map here), not the
    definition-less sniff pass, so this must be 100%.
    """
    settings = _settings(tmp_path)
    monkeypatch.setattr(verify_mod, "_load_settings", lambda: settings)
    store = RawStore(settings)
    for _ in range(10):
        store.write(make_raw_event(_PANOS_TRAFFIC_V10, source_id="t", transport="udp"))
    store.flush()

    body = json.loads(runner.invoke(app, ["verify", "roundtrip", "--json"]).stdout)

    assert body["total"] == 10
    assert body["reparse_stable"] == 10
    assert body["reparse_stable_rate"] == 100.0
    assert body["no_source_match_count"] == 0
    assert body["dead_letter_count"] == 0
    assert body["renormalize_stable_rate"] == 100.0
    assert body["failures"] == []
