"""A pure Merkle tree over SHA-256 — batch inclusion proofs in O(log n).

ULPF hashes every raw event at ingest (:mod:`ulpf.integrity.hashing`). Those
per-event digests are the **leaves** of a Merkle tree; each internal node is
``SHA-256(left_child || right_child)`` and the single **root** is a 32-byte
fingerprint of the whole batch. Publishing the root (to the hash-chain ledger,
a timestamping service, another party) commits to every event in the batch at
once.

Later, to prove that *one* event was in that batch, you do **not** re-hash and
re-scan the batch. You hand over the event's leaf hash plus an *authentication
path*: the O(log n) sibling hashes along the route from that leaf to the root.
Recomputing the root from the leaf and the path — :func:`verify_proof` — is
O(log n) hashes and needs neither the other events nor the tree itself. For a
100k-event batch that is ~17 hashes instead of 100k.

Conventions:

* **Empty batch** — the root is ``SHA-256(b"")`` (RFC 6962's MTH of the empty
  list). :func:`merkle_proof` refuses an empty tree.
* **Single leaf** — the root *is* that leaf hash; its proof is the empty path.
* **Odd level** — when a tree level has an odd number of nodes the last node is
  duplicated and paired with itself before hashing the level up.
* **Order matters** — ``merkle_root([a, b]) != merkle_root([b, a])``. Leaves are
  taken in the order given (i.e. ingest order).

Everything here is a pure function of its inputs: no I/O, no globals, no clock.
"""

from __future__ import annotations

import hashlib

# (sibling_hash, side) where side is "left" if the sibling is the left input to
# the parent hash, "right" if it is the right input.
ProofStep = tuple[bytes, str]
Proof = list[ProofStep]

_LEFT = "left"
_RIGHT = "right"


def leaf_hash(data: bytes) -> bytes:
    """Return the SHA-256 digest (32 raw bytes) of ``data`` — one Merkle leaf."""
    return hashlib.sha256(data).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Return the 32-byte Merkle root of ``leaf_hashes``.

    An empty list yields ``SHA-256(b"")``. A single leaf yields that leaf. On an
    odd level the last node is duplicated before the level is hashed upward.
    """
    if not leaf_hashes:
        return hashlib.sha256(b"").digest()

    level = [_as_hash(item) for item in leaf_hashes]
    while len(level) > 1:
        level = _hash_level(level)
    return level[0]


def merkle_proof(leaf_hashes: list[bytes], index: int) -> Proof:
    """Return the authentication path for the leaf at ``index``.

    The path is a list of ``(sibling_hash, "left" | "right")`` pairs, ordered
    from the leaf's level up to (but excluding) the root. Feed it to
    :func:`verify_proof` together with the leaf hash and the root.

    Raises:
        ValueError: if ``leaf_hashes`` is empty.
        IndexError: if ``index`` is not in ``range(len(leaf_hashes))``.
    """
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle proof for an empty tree")
    if not 0 <= index < len(leaf_hashes):
        raise IndexError(f"index {index} out of range for {len(leaf_hashes)} leaves")

    proof: Proof = []
    level = [_as_hash(item) for item in leaf_hashes]
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node
        sibling = level[idx ^ 1]  # idx^1: even -> idx+1, odd -> idx-1
        proof.append((sibling, _RIGHT if idx % 2 == 0 else _LEFT))
        level = [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_proof(leaf_hash: bytes, proof: Proof, root: bytes) -> bool:
    """Recompute the root from ``leaf_hash`` + ``proof`` and compare to ``root``.

    Returns ``True`` iff they match. A tampered leaf, sibling, side, or root all
    make this ``False``.

    Raises:
        ValueError: if a proof step has a side other than ``"left"``/``"right"``.
    """
    computed = _as_hash(leaf_hash)
    for sibling, side in proof:
        sibling = _as_hash(sibling)
        if side == _LEFT:
            computed = _hash_pair(sibling, computed)
        elif side == _RIGHT:
            computed = _hash_pair(computed, sibling)
        else:
            raise ValueError(f"invalid proof side {side!r}; expected 'left' or 'right'")
    return computed == _as_hash(root)


# -- internals -------------------------------------------------------------


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """The parent node hash: ``SHA-256(left || right)``."""
    return hashlib.sha256(left + right).digest()


def _hash_level(level: list[bytes]) -> list[bytes]:
    """Hash one full level up to its parent level, duplicating a lone last node."""
    if len(level) % 2 == 1:
        level = [*level, level[-1]]
    return [_hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]


def _as_hash(value: bytes) -> bytes:
    """Coerce ``value`` to ``bytes``; reject non-byte inputs loudly."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"leaf/hash must be bytes, got {type(value).__name__}")
