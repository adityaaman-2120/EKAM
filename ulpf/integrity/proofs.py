"""Reconstruct a single event's Merkle inclusion proof from the stored artefacts.

Given the bronze store, the per-event :class:`~ulpf.integrity.index.IntegrityIndex`,
and the signed :class:`~ulpf.integrity.ledger.IntegrityLedger`, :class:`ProofBuilder`
rebuilds — for any ``event_uid`` — the O(log n) authentication path that proves
that event was in its sealed batch, and checks:

* **hash_ok**      — re-hashing the stored raw bytes reproduces the recorded
  ``raw_hash`` (the evidence was not altered on disk);
* **proof_ok**     — that recomputed hash verifies against the batch's
  ``batch_root`` via the Merkle path (the event is genuinely in the tree);
* **signature_ok** — the batch's ledger entry carries a valid Ed25519 signature.

Per-batch leaf lists are cached so verifying every event in the store stays
cheap.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ulpf.core.models import RawEvent, sha256_hex
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import IntegrityLedger, LedgerEntry
from ulpf.integrity.merkle import Proof, merkle_proof, verify_proof
from ulpf.sinks.raw_store import RawStore

_ZERO_LEAF = b"\x00" * 32


@dataclass
class EventProof:
    """The outcome of verifying one event against the ledger."""

    event_uid: str
    found: bool  # indexed and present in a sealed batch
    hash_ok: bool  # stored bytes re-hash to the recorded raw_hash
    proof_ok: bool  # recomputed hash verifies against the batch root
    signature_ok: bool  # the batch's ledger entry signature verifies
    ledger_seq: int | None = None
    leaf_index: int | None = None
    batch_root: bytes | None = None
    chained_root: bytes | None = None
    recorded_hash: bytes | None = None
    recomputed_hash: bytes | None = None
    proof: Proof = field(default_factory=list)
    reason: str | None = None

    @property
    def ok(self) -> bool:
        """True only when every applicable check passed."""
        return self.found and self.hash_ok and self.proof_ok and self.signature_ok


class ProofBuilder:
    """Builds :class:`EventProof` results, caching per-batch leaf lists."""

    def __init__(
        self,
        raw_store: RawStore,
        index: IntegrityIndex | None,
        ledger: IntegrityLedger | None,
        *,
        event_cache: dict[str, RawEvent] | None = None,
    ) -> None:
        """Take the three stored artefacts; ``index``/``ledger`` may be absent.

        ``event_cache`` (``{event_uid: RawEvent}``) lets a caller that already
        scanned the whole bronze store — e.g. ``ulpf verify events`` — avoid the
        O(n) re-scan ``read_by_uid`` costs per sibling leaf, making a full-store
        verification O(n) instead of O(n^2).
        """
        self._store = raw_store
        self._index = index
        self._ledger = ledger
        self._event_cache = event_cache
        self._entries: dict[int, LedgerEntry] = (
            {entry.seq: entry for entry in ledger.entries()} if ledger is not None else {}
        )
        self._leaf_cache: dict[int, list[bytes]] = {}

    def for_event(self, event_uid: str) -> EventProof:
        """Verify one event end to end."""
        event = self._store.read_by_uid(event_uid)
        if event is None:
            return EventProof(
                event_uid,
                found=False,
                hash_ok=False,
                proof_ok=False,
                signature_ok=False,
                reason="event not found in the bronze store",
            )

        recorded = bytes.fromhex(event.raw_hash)
        recomputed = bytes.fromhex(sha256_hex(event.raw))
        hash_ok = recomputed == recorded

        location = self._index.lookup(event_uid) if self._index is not None else None
        if location is None or location[0] not in self._entries:
            return EventProof(
                event_uid,
                found=False,
                hash_ok=hash_ok,
                proof_ok=False,
                signature_ok=False,
                recorded_hash=recorded,
                recomputed_hash=recomputed,
                reason="no sealed ledger batch indexes this event",
            )

        seq, leaf_index = location
        entry = self._entries[seq]
        proof = merkle_proof(self._batch_leaves(seq), leaf_index)
        proof_ok = verify_proof(recomputed, proof, entry.batch_root)
        signature_ok = (
            self._ledger is not None
            and self._ledger.verifier is not None
            and self._ledger.verifier.verify(entry.chained_root, entry.signature)
        )
        return EventProof(
            event_uid,
            found=True,
            hash_ok=hash_ok,
            proof_ok=proof_ok,
            signature_ok=bool(signature_ok),
            ledger_seq=seq,
            leaf_index=leaf_index,
            batch_root=entry.batch_root,
            chained_root=entry.chained_root,
            recorded_hash=recorded,
            recomputed_hash=recomputed,
            proof=proof,
        )

    def _batch_leaves(self, seq: int) -> list[bytes]:
        """The recorded leaf hashes of batch ``seq``, in leaf order (cached)."""
        if seq not in self._leaf_cache:
            assert self._index is not None
            leaves = []
            for uid in self._index.event_uids_for_batch(seq):
                sibling = (
                    self._event_cache.get(uid)
                    if self._event_cache is not None
                    else self._store.read_by_uid(uid)
                )
                leaves.append(bytes.fromhex(sibling.raw_hash) if sibling else _ZERO_LEAF)
            self._leaf_cache[seq] = leaves
        return self._leaf_cache[seq]
