"""Tests for :mod:`ulpf.integrity.ledger`."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ulpf.config.settings import Settings, StorageSettings
from ulpf.integrity.ledger import (
    GENESIS_ROOT,
    LEDGER_FILENAME,
    IntegrityLedger,
    chain_roots,
)
from ulpf.integrity.merkle import merkle_root
from ulpf.integrity.signing import Signer, Verifier


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(ledger_path=tmp_path / "ledger"))


def _signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())


def _leaves(n: int, salt: str = "") -> list[bytes]:
    return [hashlib.sha256(f"{salt}event-{i}".encode()).digest() for i in range(n)]


def _ledger_file(tmp_path: Path) -> Path:
    return tmp_path / "ledger" / LEDGER_FILENAME


def _rewrite_line(path: Path, index: int, new_line: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[index] = new_line
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# appending


def test_first_entry_uses_the_genesis_prev_root(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)

    entry = ledger.append_batch(_leaves(8))

    assert entry.seq == 0
    assert entry.prev_chained_root == GENESIS_ROOT == b"\x00" * 32
    assert entry.batch_root == merkle_root(_leaves(8))
    assert entry.chained_root == chain_roots(GENESIS_ROOT, entry.batch_root)
    assert entry.leaf_count == 8
    assert signer.verifier().verify(entry.chained_root, entry.signature) is True
    assert ledger.head == entry.chained_root


def test_entries_are_hash_chained(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    e0 = ledger.append_batch(_leaves(3, "a"))
    e1 = ledger.append_batch(_leaves(5, "b"))
    e2 = ledger.append_batch(_leaves(2, "c"))

    assert [e.seq for e in (e0, e1, e2)] == [0, 1, 2]
    assert e1.prev_chained_root == e0.chained_root
    assert e2.prev_chained_root == e1.chained_root
    assert e1.chained_root == chain_roots(e0.chained_root, e1.batch_root)
    assert e2.chained_root == chain_roots(e1.chained_root, e2.batch_root)


def test_event_uid_bounds_are_recorded_when_supplied(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    with_uids = ledger.append_batch(_leaves(4), event_uids=["uid-a", "uid-b", "uid-c", "uid-d"])
    without = ledger.append_batch(_leaves(4))

    assert (with_uids.first_event_uid, with_uids.last_event_uid) == ("uid-a", "uid-d")
    assert without.first_event_uid is None and without.last_event_uid is None


def test_empty_batch_still_appends_and_chains(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    ledger.append_batch(_leaves(3))
    empty = ledger.append_batch([])

    assert empty.leaf_count == 0
    assert empty.batch_root == hashlib.sha256(b"").digest()
    assert ledger.verify_chain() == (True, None)


def test_signature_covers_the_chained_root_not_the_batch_root(tmp_path: Path) -> None:
    signer = _signer()
    entry = IntegrityLedger(_settings(tmp_path), signer).append_batch(_leaves(6))
    verifier = signer.verifier()

    assert verifier.verify(entry.chained_root, entry.signature) is True
    assert verifier.verify(entry.batch_root, entry.signature) is False


# --------------------------------------------------------------------------
# persistence


def test_persisted_as_append_only_ndjson(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    ledger.append_batch(_leaves(2))
    path = _ledger_file(tmp_path)
    first_line = path.read_text(encoding="utf-8").splitlines()[0]

    ledger.append_batch(_leaves(2))
    lines = path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2
    assert lines[0] == first_line  # the earlier line was not rewritten
    row = json.loads(lines[1])
    assert set(row) == {
        "seq",
        "batch_root",
        "prev_chained_root",
        "chained_root",
        "leaf_count",
        "first_event_uid",
        "last_event_uid",
        "sealed_at_ns",
        "signature",
    }
    assert row["seq"] == 1 and len(row["signature"]) == 128  # 64 bytes hex


def test_reopening_the_ledger_continues_the_chain(tmp_path: Path) -> None:
    signer = _signer()
    first = IntegrityLedger(_settings(tmp_path), signer)
    first.append_batch(_leaves(3))
    e1 = first.append_batch(_leaves(4))

    reopened = IntegrityLedger(_settings(tmp_path), signer)
    assert len(reopened) == 2
    assert reopened.head == e1.chained_root

    e2 = reopened.append_batch(_leaves(5))
    assert e2.seq == 2 and e2.prev_chained_root == e1.chained_root
    assert reopened.verify_chain() == (True, None)


# --------------------------------------------------------------------------
# verify_chain


def test_verify_chain_passes_for_a_healthy_ledger(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    for i in range(6):
        ledger.append_batch(_leaves(i + 1, salt=str(i)))
    assert ledger.verify_chain() == (True, None)


def test_verify_chain_passes_for_an_empty_ledger(tmp_path: Path) -> None:
    assert IntegrityLedger(_settings(tmp_path), _signer()).verify_chain() == (True, None)


def test_verify_chain_catches_a_corrupted_line_at_its_sequence_number(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)
    for i in range(5):
        ledger.append_batch(_leaves(4, salt=str(i)))
    path = _ledger_file(tmp_path)

    # tamper with the batch_root on entry seq=2 -> its chained_root no longer
    # recomputes, so the chain breaks exactly there.
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[2])
    row["batch_root"] = "ff" * 32
    _rewrite_line(path, 2, json.dumps(row, separators=(",", ":")))

    assert IntegrityLedger(_settings(tmp_path), signer).verify_chain() == (False, 2)


def test_verify_chain_catches_a_forged_signature(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)
    for i in range(4):
        ledger.append_batch(_leaves(3, salt=str(i)))
    path = _ledger_file(tmp_path)

    row = json.loads(path.read_text(encoding="utf-8").splitlines()[3])
    sig = bytearray.fromhex(row["signature"])
    sig[0] ^= 0x01
    row["signature"] = sig.hex()
    _rewrite_line(path, 3, json.dumps(row, separators=(",", ":")))

    assert IntegrityLedger(_settings(tmp_path), signer).verify_chain() == (False, 3)


def test_verify_chain_catches_a_broken_link(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)
    for i in range(4):
        ledger.append_batch(_leaves(3, salt=str(i)))
    path = _ledger_file(tmp_path)

    row = json.loads(path.read_text(encoding="utf-8").splitlines()[1])
    row["prev_chained_root"] = "ab" * 32  # does not match entry 0's chained_root
    _rewrite_line(path, 1, json.dumps(row, separators=(",", ":")))

    assert IntegrityLedger(_settings(tmp_path), signer).verify_chain() == (False, 1)


def test_verify_chain_catches_unparseable_json(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)
    for i in range(3):
        ledger.append_batch(_leaves(2, salt=str(i)))
    _rewrite_line(_ledger_file(tmp_path), 1, "{ this is not json")

    assert IntegrityLedger(_settings(tmp_path), signer).verify_chain() == (False, 1)


def test_verify_chain_catches_a_dropped_entry(tmp_path: Path) -> None:
    signer = _signer()
    ledger = IntegrityLedger(_settings(tmp_path), signer)
    for i in range(5):
        ledger.append_batch(_leaves(2, salt=str(i)))
    path = _ledger_file(tmp_path)

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[2]  # remove seq=2; seq=3 now sits at line index 2
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, broken_at = IntegrityLedger(_settings(tmp_path), signer).verify_chain()
    assert ok is False and broken_at == 2


def test_verify_chain_fails_under_a_wrong_public_key(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    ledger.append_batch(_leaves(4))

    other = Verifier(Ed25519PrivateKey.generate().public_key())
    checker = IntegrityLedger(_settings(tmp_path), _signer(), verifier=other)
    assert checker.verify_chain() == (False, 0)


def test_entries_reads_back_what_was_written(tmp_path: Path) -> None:
    ledger = IntegrityLedger(_settings(tmp_path), _signer())
    written = [ledger.append_batch(_leaves(i + 1, salt=str(i))) for i in range(4)]
    assert ledger.entries() == written
