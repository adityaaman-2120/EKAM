"""Tests for :mod:`ulpf.integrity.merkle`."""

from __future__ import annotations

import hashlib

import pytest

from ulpf.integrity.merkle import leaf_hash, merkle_proof, merkle_root, verify_proof


def _leaves(n: int) -> list[bytes]:
    return [hashlib.sha256(f"event-{i}".encode()).digest() for i in range(n)]


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


# --------------------------------------------------------------------------
# merkle_root — structural cases


def test_empty_batch_root_is_sha256_of_empty() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_leaf_itself() -> None:
    (a,) = _leaves(1)
    assert merkle_root([a]) == a


def test_two_leaves_root_is_the_pair_hash() -> None:
    a, b = _leaves(2)
    assert merkle_root([a, b]) == _h(a, b)


def test_odd_level_duplicates_the_last_node() -> None:
    a, b, c = _leaves(3)
    # level 0: [a, b, c] -> dup -> [a, b, c, c]
    # level 1: [H(a,b), H(c,c)]
    # root:    H( H(a,b), H(c,c) )
    assert merkle_root([a, b, c]) == _h(_h(a, b), _h(c, c))


def test_four_leaves_is_a_balanced_tree() -> None:
    a, b, c, d = _leaves(4)
    assert merkle_root([a, b, c, d]) == _h(_h(a, b), _h(c, d))


def test_root_is_deterministic_and_order_sensitive() -> None:
    a, b = _leaves(2)
    assert merkle_root([a, b]) == merkle_root([a, b])
    assert merkle_root([a, b]) != merkle_root([b, a])


def test_root_is_always_32_bytes() -> None:
    for n in (0, 1, 2, 3, 5, 17, 64):
        assert len(merkle_root(_leaves(n))) == 32


def test_non_bytes_leaf_is_rejected() -> None:
    with pytest.raises(TypeError):
        merkle_root(["not-bytes"])  # type: ignore[list-item]


def test_bytearray_and_memoryview_leaves_are_accepted() -> None:
    a, b = _leaves(2)
    assert merkle_root([bytearray(a), memoryview(b)]) == _h(a, b)


# --------------------------------------------------------------------------
# merkle_proof / verify_proof


def test_single_leaf_proof_is_empty_and_verifies() -> None:
    (a,) = _leaves(1)
    proof = merkle_proof([a], 0)
    assert proof == []
    assert verify_proof(a, proof, merkle_root([a])) is True


def test_two_leaf_proofs_name_the_correct_sibling_and_side() -> None:
    a, b = _leaves(2)
    root = merkle_root([a, b])
    assert merkle_proof([a, b], 0) == [(b, "right")]
    assert merkle_proof([a, b], 1) == [(a, "left")]
    assert verify_proof(a, [(b, "right")], root) is True
    assert verify_proof(b, [(a, "left")], root) is True


def test_odd_tree_proof_pairs_the_last_leaf_with_itself() -> None:
    a, b, c = _leaves(3)
    root = merkle_root([a, b, c])
    proof = merkle_proof([a, b, c], 2)
    assert proof == [(c, "right"), (_h(a, b), "left")]
    assert verify_proof(c, proof, root) is True


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 100, 999, 1000])
def test_every_index_produces_a_verifiable_proof(n: int) -> None:
    leaves = _leaves(n)
    root = merkle_root(leaves)
    for index in range(n):
        proof = merkle_proof(leaves, index)
        assert verify_proof(leaves[index], proof, root) is True, f"n={n} index={index}"


@pytest.mark.parametrize("n", [2, 3, 4, 5, 8, 9, 1000])
def test_proof_length_is_ceil_log2_n(n: int) -> None:
    expected = (n - 1).bit_length()  # ceil(log2(n)) for n >= 2
    proof = merkle_proof(_leaves(n), 0)
    assert len(proof) == expected


def test_1000_leaves_every_index_verifies_against_the_one_published_root() -> None:
    leaves = _leaves(1000)
    root = merkle_root(leaves)
    assert len(root) == 32
    for index in range(1000):
        assert verify_proof(leaves[index], merkle_proof(leaves, index), root)
    assert len(merkle_proof(leaves, 0)) == 10  # ceil(log2(1000))


# --------------------------------------------------------------------------
# tamper detection


def test_altered_leaf_fails_verification() -> None:
    leaves = _leaves(50)
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 7)
    assert verify_proof(leaves[7], proof, root) is True

    tampered = bytearray(leaves[7])
    tampered[0] ^= 0x01
    assert verify_proof(bytes(tampered), proof, root) is False


def test_altered_sibling_in_the_path_fails_verification() -> None:
    leaves = _leaves(20)
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 3)

    sibling, side = proof[0]
    bad_sibling = bytearray(sibling)
    bad_sibling[-1] ^= 0xFF
    broken = [(bytes(bad_sibling), side), *proof[1:]]
    assert verify_proof(leaves[3], broken, root) is False


def test_wrong_root_fails_verification() -> None:
    leaves = _leaves(16)
    proof = merkle_proof(leaves, 5)
    assert verify_proof(leaves[5], proof, b"\x00" * 32) is False


def test_proof_for_a_different_index_does_not_verify() -> None:
    leaves = _leaves(33)
    root = merkle_root(leaves)
    proof_for_1 = merkle_proof(leaves, 1)
    assert verify_proof(leaves[0], proof_for_1, root) is False


def test_swapped_side_token_fails_verification() -> None:
    a, b = _leaves(2)
    root = merkle_root([a, b])
    assert verify_proof(a, [(b, "left")], root) is False  # should be "right"


def test_a_leaf_from_another_batch_does_not_verify() -> None:
    batch = _leaves(64)
    root = merkle_root(batch)
    outsider = hashlib.sha256(b"never-ingested").digest()
    # borrow a real path but swap in a foreign leaf
    assert verify_proof(outsider, merkle_proof(batch, 10), root) is False


# --------------------------------------------------------------------------
# error handling


def test_empty_tree_has_no_proof() -> None:
    with pytest.raises(ValueError):
        merkle_proof([], 0)


@pytest.mark.parametrize("bad_index", [-1, 5, 6, 999])
def test_out_of_range_index_raises(bad_index: int) -> None:
    with pytest.raises(IndexError):
        merkle_proof(_leaves(5), bad_index)


def test_verify_proof_rejects_an_invalid_side() -> None:
    a, b = _leaves(2)
    with pytest.raises(ValueError):
        verify_proof(a, [(b, "middle")], merkle_root([a, b]))


def test_leaf_hash_helper_matches_plain_sha256() -> None:
    assert leaf_hash(b"raw event bytes") == hashlib.sha256(b"raw event bytes").digest()
    assert len(leaf_hash(b"")) == 32
