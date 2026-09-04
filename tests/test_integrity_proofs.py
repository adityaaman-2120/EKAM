"""Tests for :mod:`ulpf.integrity.proofs`."""

from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ulpf.config.settings import IntegritySettings, Settings, StorageSettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import IntegrityLedger
from ulpf.integrity.proofs import ProofBuilder
from ulpf.integrity.signing import Signer
from ulpf.sinks.raw_store import RawStore


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(bronze_path=tmp_path / "bronze", ledger_path=tmp_path / "ledger"),
        integrity=IntegritySettings(),
    )


def _populate(tmp_path: Path, n: int = 4):  # noqa: ANN202
    settings = _settings(tmp_path)
    signer = Signer(Ed25519PrivateKey.generate())
    store = RawStore(settings)
    events = [
        make_raw_event(f"raw evt {i}".encode(), source_id="t", transport="udp") for i in range(n)
    ]
    for event in events:
        store.write(event)
    store.flush()

    ledger = IntegrityLedger(settings, signer)
    index = IntegrityIndex(tmp_path / "ledger" / "event_index.sqlite")
    uids = [e.event_uid for e in events]
    entry = ledger.append_batch([bytes.fromhex(e.raw_hash) for e in events], event_uids=uids)
    index.add_batch(entry.seq, uids)
    return settings, events, RawStore(settings), index, IntegrityLedger(settings, signer)


def _tamper_bronze(settings: Settings, event_uid: str) -> None:
    path = next(Path(settings.storage.bronze_path).rglob("events.ndjson.gz"))
    with gzip.open(path, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == event_uid:
            record["raw_b64"] = base64.b64encode(b"TAMPERED PAYLOAD").decode("ascii")
    with gzip.open(path, "wb") as handle:
        for record in records:
            handle.write(
                (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            )


def test_proof_for_a_clean_event_verifies_end_to_end(tmp_path: Path) -> None:
    _settings_, events, store, index, ledger = _populate(tmp_path, 4)
    proof = ProofBuilder(store, index, ledger).for_event(events[2].event_uid)

    assert proof.ok is True
    assert proof.hash_ok and proof.proof_ok and proof.signature_ok
    assert (proof.ledger_seq, proof.leaf_index) == (0, 2)
    assert proof.recorded_hash == proof.recomputed_hash
    assert len(proof.proof) == 2  # ceil(log2(4))


def test_unknown_event_is_reported_missing(tmp_path: Path) -> None:
    _settings_, _events, store, index, ledger = _populate(tmp_path)
    proof = ProofBuilder(store, index, ledger).for_event("no-such-uid")
    assert proof.found is False and proof.ok is False
    assert "not found" in (proof.reason or "")


def test_without_a_ledger_only_the_hash_is_checked(tmp_path: Path) -> None:
    _settings_, events, store, _index, _ledger = _populate(tmp_path)
    proof = ProofBuilder(store, None, None).for_event(events[0].event_uid)
    assert proof.hash_ok is True
    assert proof.found is False and proof.ok is False
    assert "no sealed ledger batch" in (proof.reason or "")


def test_a_tampered_event_fails_both_the_hash_and_the_proof(tmp_path: Path) -> None:
    settings, events, _store, index, ledger = _populate(tmp_path, 4)
    _tamper_bronze(settings, events[1].event_uid)

    proof = ProofBuilder(RawStore(settings), index, ledger).for_event(events[1].event_uid)
    assert proof.hash_ok is False
    assert proof.proof_ok is False  # the recomputed hash is not in the sealed tree
    assert proof.ok is False
    # its neighbours still verify
    assert ProofBuilder(RawStore(settings), index, ledger).for_event(events[0].event_uid).ok is True
