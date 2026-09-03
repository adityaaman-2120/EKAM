"""The chained, signed root ledger — ULPF's honest answer to the "blockchain" theme.

WHY A HASH-CHAINED BATCH LEDGER, NOT PER-EVENT CONSENSUS
-------------------------------------------------------
A literal blockchain writes (and, in most designs, reaches consensus on) one
record per event. That caps sustained throughput at **hundreds of events per
second**: every event pays for a durable append, an fsync, and — on a real
distributed ledger — a consensus round-trip. A perimeter that emits 50k–150k
EPS during an incident would fall hours behind, which is exactly when integrity
evidence matters most.

ULPF instead:

1. hashes every raw event at ingest (tamper-evident from the first byte);
2. groups those leaf hashes into batches and folds each batch into one 32-byte
   **Merkle root** (:mod:`ulpf.integrity.merkle`);
3. writes **one ledger entry per batch**, hash-chained to the previous entry and
   Ed25519-signed.

Per-batch writes are ~1/1000th the I/O of per-event writes, so the ledger keeps
up with **100k+ EPS** on a single node. Detection power is not lost: altering,
inserting, or dropping a single event changes its batch's Merkle root, which
changes that entry's ``chained_root``, which breaks the signature and every
subsequent link. An auditor proves any one event belongs to its batch with an
O(log n) Merkle path (:func:`ulpf.integrity.merkle.merkle_proof`) and proves the
batch belongs to history by verifying the chain here.

LEDGER ENTRY
------------
One :class:`LedgerEntry` per batch, persisted as NDJSON (one JSON object per
line) to ``<ledger_path>/ledger.ndjson``, append-only:

* ``seq``               — 0-based position; equals the line number.
* ``batch_root``        — Merkle root of this batch's leaf hashes.
* ``prev_chained_root`` — the previous entry's ``chained_root``; 32 zero bytes
  for ``seq == 0`` (genesis).
* ``chained_root``      — ``SHA-256(prev_chained_root || batch_root)``.
* ``leaf_count``        — number of events in the batch.
* ``first_event_uid`` / ``last_event_uid`` — batch bounds (operator context;
  present only when the caller supplies the UIDs).
* ``sealed_at_ns``      — UTC epoch nanoseconds the entry was written.
* ``signature``         — Ed25519 signature over ``chained_root``.

The signed material is ``chained_root`` alone; it transitively commits to every
batch root — and thus, via the Merkle trees, every event — back to genesis.

:meth:`IntegrityLedger.verify_chain` re-reads the file, recomputes every
``chained_root`` from ``prev_chained_root`` + ``batch_root``, checks every link
and ``seq``, and verifies every signature, returning ``(ok, broken_at)`` where
``broken_at`` is the sequence number of the first bad entry.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from ulpf.config.settings import Settings
from ulpf.integrity.merkle import merkle_root
from ulpf.integrity.signing import Signer, Verifier

GENESIS_ROOT = b"\x00" * 32
LEDGER_FILENAME = "ledger.ndjson"

_HASH_LEN = 32
_SIG_LEN = 64


@dataclass(frozen=True)
class LedgerEntry:
    """One batch's chained, signed ledger record."""

    seq: int
    batch_root: bytes
    prev_chained_root: bytes
    chained_root: bytes
    leaf_count: int
    first_event_uid: str | None
    last_event_uid: str | None
    sealed_at_ns: int
    signature: bytes

    def to_json(self) -> str:
        """Serialize to a single NDJSON line (byte fields as lowercase hex)."""
        return json.dumps(
            {
                "seq": self.seq,
                "batch_root": self.batch_root.hex(),
                "prev_chained_root": self.prev_chained_root.hex(),
                "chained_root": self.chained_root.hex(),
                "leaf_count": self.leaf_count,
                "first_event_uid": self.first_event_uid,
                "last_event_uid": self.last_event_uid,
                "sealed_at_ns": self.sealed_at_ns,
                "signature": self.signature.hex(),
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, line: str) -> LedgerEntry:
        """Parse one NDJSON line; raises ``ValueError`` on malformed input."""
        try:
            data = json.loads(line)
            entry = cls(
                seq=int(data["seq"]),
                batch_root=bytes.fromhex(data["batch_root"]),
                prev_chained_root=bytes.fromhex(data["prev_chained_root"]),
                chained_root=bytes.fromhex(data["chained_root"]),
                leaf_count=int(data["leaf_count"]),
                first_event_uid=data.get("first_event_uid"),
                last_event_uid=data.get("last_event_uid"),
                sealed_at_ns=int(data["sealed_at_ns"]),
                signature=bytes.fromhex(data["signature"]),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed ledger line: {exc}") from exc
        if (
            len(entry.batch_root) != _HASH_LEN
            or len(entry.prev_chained_root) != _HASH_LEN
            or len(entry.chained_root) != _HASH_LEN
            or len(entry.signature) != _SIG_LEN
        ):
            raise ValueError("ledger line has a wrong-length hash or signature")
        return entry


def chain_roots(prev_chained_root: bytes, batch_root: bytes) -> bytes:
    """``SHA-256(prev_chained_root || batch_root)`` — the chain step."""
    return hashlib.sha256(prev_chained_root + batch_root).digest()


class IntegrityLedger:
    """Append-only, hash-chained, Ed25519-signed ledger of batch Merkle roots."""

    def __init__(
        self,
        settings: Settings,
        signer: Signer | None = None,
        *,
        verifier: Verifier | None = None,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        """Open (or create) ``<ledger_path>/ledger.ndjson`` and read its tail state.

        ``signer`` is required only to :meth:`append_batch`; a read-only /
        verify-only ledger can be opened with just a ``verifier`` (an auditor's
        public key).
        """
        self._path = Path(settings.storage.ledger_path) / LEDGER_FILENAME
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._signer = signer
        self._verifier = verifier or (signer.verifier() if signer is not None else None)
        self._clock = clock

        self._next_seq = 0
        self._prev_chained_root = GENESIS_ROOT
        for line in self._read_lines():
            try:
                entry = LedgerEntry.from_json(line)
            except ValueError:
                break  # stop at the first unreadable line; verify_chain reports it
            self._next_seq = entry.seq + 1
            self._prev_chained_root = entry.chained_root

    @property
    def head(self) -> bytes:
        """The most recent ``chained_root`` (genesis root if the ledger is empty)."""
        return self._prev_chained_root

    @property
    def verifier(self) -> Verifier | None:
        """The signature verifier this ledger checks entries with, if any."""
        return self._verifier

    def __len__(self) -> int:
        """Number of entries appended (== next sequence number)."""
        return self._next_seq

    def append_batch(
        self, leaf_hashes: list[bytes], *, event_uids: Sequence[str] | None = None
    ) -> LedgerEntry:
        """Fold ``leaf_hashes`` into a Merkle root, chain + sign it, and persist.

        ``event_uids`` (optional) only fills ``first_event_uid`` /
        ``last_event_uid``; it does not have to line up with ``leaf_hashes``.
        """
        if self._signer is None:
            raise RuntimeError("ledger opened read-only; no signer to append with")
        batch_root = merkle_root(leaf_hashes)
        prev = self._prev_chained_root
        chained_root = chain_roots(prev, batch_root)
        entry = LedgerEntry(
            seq=self._next_seq,
            batch_root=batch_root,
            prev_chained_root=prev,
            chained_root=chained_root,
            leaf_count=len(leaf_hashes),
            first_event_uid=event_uids[0] if event_uids else None,
            last_event_uid=event_uids[-1] if event_uids else None,
            sealed_at_ns=self._clock(),
            signature=self._signer.sign(chained_root),
        )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json() + "\n")
        self._prev_chained_root = chained_root
        self._next_seq += 1
        return entry

    def entries(self) -> list[LedgerEntry]:
        """Every entry currently on disk (raises ``ValueError`` on a corrupt line)."""
        return [LedgerEntry.from_json(line) for line in self._read_lines()]

    def entry_count_on_disk(self) -> int:
        """Number of NDJSON lines currently in the ledger file (for progress bars)."""
        return len(self._read_lines())

    def iter_checked(self) -> Iterator[tuple[int, LedgerEntry | None, str | None]]:
        """Yield ``(index, entry, reason)`` for each line, stopping after the first fault.

        ``reason`` is ``None`` when the entry is sound; otherwise a short string
        naming the broken check. ``entry`` is ``None`` only when the line could
        not be parsed.
        """
        prev = GENESIS_ROOT
        for index, line in enumerate(self._read_lines()):
            entry, reason = self._check_line(index, line, prev)
            yield index, entry, reason
            if reason is not None:
                return
            assert entry is not None
            prev = entry.chained_root

    def verify_chain(self) -> tuple[bool, int | None]:
        """Re-read the file and check every link, ``seq``, and signature.

        Returns ``(True, None)`` for an intact (or empty) ledger, else
        ``(False, seq)`` where ``seq`` is the position of the first bad entry
        (the line index, which a well-formed ledger keeps equal to ``entry.seq``).
        """
        for index, _entry, reason in self.iter_checked():
            if reason is not None:
                return False, index
        return True, None

    # -- internals ------------------------------------------------------

    def _check_line(
        self, index: int, line: str, prev_chained_root: bytes
    ) -> tuple[LedgerEntry | None, str | None]:
        """Validate one ledger line against ``prev_chained_root``; ``(entry, reason)``."""
        try:
            entry = LedgerEntry.from_json(line)
        except ValueError as exc:
            return None, f"unparseable line: {exc}"
        if entry.seq != index:
            return entry, f"seq {entry.seq} does not match position {index}"
        if entry.prev_chained_root != prev_chained_root:
            return entry, "prev_chained_root does not link to the previous entry"
        if chain_roots(entry.prev_chained_root, entry.batch_root) != entry.chained_root:
            return entry, "chained_root does not recompute from prev_chained_root + batch_root"
        if self._verifier is None:
            return entry, "no public key configured; cannot verify the signature"
        if not self._verifier.verify(entry.chained_root, entry.signature):
            return entry, "Ed25519 signature is invalid"
        return entry, None

    def _read_lines(self) -> list[str]:
        """Non-empty lines of the ledger file, or ``[]`` if it does not exist yet."""
        if not self._path.is_file():
            return []
        text = self._path.read_text(encoding="utf-8")
        return [line for line in text.splitlines() if line.strip()]
