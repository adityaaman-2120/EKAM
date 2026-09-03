"""Tests for :class:`ulpf.integrity.stage.IntegrityStage`."""

from __future__ import annotations

import asyncio
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ulpf.config.settings import IntegritySettings, Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.integrity.ledger import IntegrityLedger
from ulpf.integrity.merkle import merkle_proof, verify_proof
from ulpf.integrity.signing import Signer
from ulpf.integrity.stage import IntegrityStage
from ulpf.integrity.hashing import make_raw_event


def _signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())


def _settings(tmp_path: Path, **integrity: object) -> Settings:
    opts: dict[str, object] = {"batch_size": 3, "batch_timeout_seconds": 0.0}
    opts.update(integrity)
    return Settings(
        storage=StorageSettings(ledger_path=tmp_path / "ledger", bronze_path=tmp_path / "b"),
        integrity=IntegritySettings(**opts),
    )


def _events(n: int):  # noqa: ANN202
    return [make_raw_event(f"raw event {i}".encode(), source_id="s", transport="udp") for i in range(n)]


async def _feed(stage: IntegrityStage, events) -> None:  # noqa: ANN001
    for event in events:
        assert await stage.process(event) is event  # passed through unchanged


# --------------------------------------------------------------------------
# size-triggered seal


async def test_seals_when_the_batch_reaches_batch_size(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=3)
    signer = _signer()
    stage = IntegrityStage(settings, signer=signer)
    events = _events(4)
    key = 'ulpf_integrity_batches_sealed_total{trigger="size"}'
    before = snapshot().get(key, 0.0)

    await _feed(stage, events)

    assert stage.pending_count() == 1  # the 4th event is in the open batch
    entries = stage.ledger.entries()
    assert len(entries) == 1
    entry = entries[0]
    assert entry.leaf_count == 3
    assert entry.first_event_uid == events[0].event_uid
    assert entry.last_event_uid == events[2].event_uid
    assert signer.verifier().verify(entry.chained_root, entry.signature) is True

    assert stage.index.lookup(events[0].event_uid) == (0, 0)
    assert stage.index.lookup(events[2].event_uid) == (0, 2)
    assert stage.index.lookup(events[3].event_uid) is None  # not sealed yet
    assert snapshot()[key] - before == 1.0

    await stage.flush()


# --------------------------------------------------------------------------
# timeout-triggered seal


async def test_seals_when_the_timeout_elapses_with_no_new_events(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=100, batch_timeout_seconds=0.3)
    stage = IntegrityStage(settings, signer=_signer())
    events = _events(2)
    key = 'ulpf_integrity_batches_sealed_total{trigger="timeout"}'
    before = snapshot().get(key, 0.0)

    try:
        await _feed(stage, events)
        assert stage.pending_count() == 2
        await asyncio.sleep(0.9)  # let the background poll fire

        assert stage.pending_count() == 0
        entries = stage.ledger.entries()
        assert len(entries) == 1 and entries[0].leaf_count == 2
        assert snapshot()[key] - before == 1.0
    finally:
        await stage.flush()


# --------------------------------------------------------------------------
# shutdown seals the partial batch


async def test_flush_seals_the_partial_batch_on_shutdown(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=100, batch_timeout_seconds=0.0)
    signer = _signer()
    stage = IntegrityStage(settings, signer=signer)
    events = _events(4)
    key = 'ulpf_integrity_batches_sealed_total{trigger="shutdown"}'
    before = snapshot().get(key, 0.0)

    await _feed(stage, events)
    assert stage.pending_count() == 4
    assert stage.ledger.entries() == []  # nothing sealed yet

    await stage.flush()

    entries = stage.ledger.entries()
    assert len(entries) == 1 and entries[0].leaf_count == 4
    assert snapshot()[key] - before == 1.0
    # the ledger persisted and verifies with a fresh reader
    assert IntegrityLedger(settings, signer).verify_chain() == (True, None)


async def test_flush_with_no_pending_events_seals_nothing(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=100, batch_timeout_seconds=0.0)
    stage = IntegrityStage(settings, signer=_signer())
    await stage.flush()
    assert stage.ledger.entries() == []


# --------------------------------------------------------------------------
# chaining, persistence, proof reconstruction


async def test_multiple_batches_are_hash_chained(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=2, batch_timeout_seconds=0.0)
    signer = _signer()
    stage = IntegrityStage(settings, signer=signer)

    await _feed(stage, _events(6))
    assert [e.seq for e in stage.ledger.entries()] == [0, 1, 2]
    assert len(stage.index) == 6

    await stage.flush()  # closes the index
    assert IntegrityLedger(settings, signer).verify_chain() == (True, None)


async def test_index_lets_a_proof_be_rebuilt_without_a_rescan(tmp_path: Path) -> None:
    settings = _settings(tmp_path, batch_size=5, batch_timeout_seconds=0.0)
    stage = IntegrityStage(settings, signer=_signer())
    events = _events(5)
    leaves = [bytes.fromhex(e.raw_hash) for e in events]  # the batch's Merkle leaves

    await _feed(stage, events)

    seq, leaf_index = stage.index.lookup(events[3].event_uid)
    assert (seq, leaf_index) == (0, 3)
    entry = stage.ledger.entries()[seq]

    proof = merkle_proof(leaves, leaf_index)
    assert verify_proof(leaves[leaf_index], proof, entry.batch_root) is True
    # a different event's leaf must not verify against this path
    assert verify_proof(leaves[0], proof, entry.batch_root) is False

    await stage.flush()


# --------------------------------------------------------------------------
# disabled


async def test_disabled_when_integrity_is_off(tmp_path: Path) -> None:
    settings = _settings(tmp_path, enabled=False)
    stage = IntegrityStage(settings, signer=_signer())

    await _feed(stage, _events(5))
    await stage.flush()

    assert stage.enabled is False
    assert stage.ledger is None and stage.index is None
    assert not (tmp_path / "ledger" / "ledger.ndjson").exists()


async def test_disabled_when_no_signing_key(tmp_path: Path) -> None:
    stage = IntegrityStage(_settings(tmp_path), signer=None)
    await _feed(stage, _events(5))
    assert stage.enabled is False
    await stage.flush()
