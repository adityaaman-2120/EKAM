"""Tests for :mod:`ulpf.integrity.index`."""

from __future__ import annotations

from pathlib import Path

from ulpf.integrity.index import IntegrityIndex


def _index(tmp_path: Path) -> IntegrityIndex:
    return IntegrityIndex(tmp_path / "ledger" / "event_index.sqlite")


def test_add_batch_maps_each_event_to_its_leaf_index(tmp_path: Path) -> None:
    index = _index(tmp_path)
    index.add_batch(0, ["a", "b", "c"])
    index.add_batch(1, ["d", "e"])

    assert index.lookup("a") == (0, 0)
    assert index.lookup("c") == (0, 2)
    assert index.lookup("d") == (1, 0)
    assert index.lookup("e") == (1, 1)
    assert len(index) == 5
    index.close()


def test_lookup_miss_returns_none(tmp_path: Path) -> None:
    index = _index(tmp_path)
    index.add_batch(0, ["x"])
    assert index.lookup("nope") is None
    index.close()


def test_event_uids_for_batch_is_ordered_by_leaf_index(tmp_path: Path) -> None:
    index = _index(tmp_path)
    index.add_batch(7, ["u0", "u1", "u2", "u3"])
    assert index.event_uids_for_batch(7) == ["u0", "u1", "u2", "u3"]
    assert index.event_uids_for_batch(99) == []
    index.close()


def test_index_persists_across_reopen(tmp_path: Path) -> None:
    first = _index(tmp_path)
    first.add_batch(3, ["p", "q"])
    first.close()

    reopened = _index(tmp_path)
    assert reopened.lookup("q") == (3, 1)
    assert len(reopened) == 2
    reopened.close()


def test_reindexing_an_event_replaces_the_row(tmp_path: Path) -> None:
    index = _index(tmp_path)
    index.add_batch(0, ["a"])
    index.add_batch(1, ["a"])  # same uid, different batch
    assert index.lookup("a") == (1, 0)
    assert len(index) == 1
    index.close()
