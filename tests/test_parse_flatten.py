"""Tests for :func:`ulpf.parse.engines.util.flatten`."""

from __future__ import annotations

from ulpf.parse.engines.util import flatten


def test_already_flat_dict_is_unchanged() -> None:
    assert flatten({"a": 1, "b": "x", "c": True}) == {"a": 1, "b": "x", "c": True}


def test_nested_dicts_become_dotted_keys() -> None:
    assert flatten({"a": {"b": {"c": 1}}}) == {"a.b.c": 1}


def test_list_index_becomes_part_of_the_key() -> None:
    assert flatten({"tags": ["x", "y", "z"]}) == {
        "tags.0": "x",
        "tags.1": "y",
        "tags.2": "z",
    }


def test_list_of_dicts() -> None:
    assert flatten({"users": [{"name": "a"}, {"name": "b"}]}) == {
        "users.0.name": "a",
        "users.1.name": "b",
    }


def test_deeply_nested_mixed_dicts_and_lists() -> None:
    obj = {
        "event": {
            "src": {"ip": "192.0.2.1", "ports": [80, 443]},
            "path": [{"hop": 1}, {"hop": 2, "asn": [64500, 64501]}],
        },
        "ok": True,
    }
    assert flatten(obj) == {
        "event.src.ip": "192.0.2.1",
        "event.src.ports.0": 80,
        "event.src.ports.1": 443,
        "event.path.0.hop": 1,
        "event.path.1.hop": 2,
        "event.path.1.asn.0": 64500,
        "event.path.1.asn.1": 64501,
        "ok": True,
    }


def test_prefix_is_applied_to_every_key() -> None:
    assert flatten({"x": 1, "y": {"z": 2}}, prefix="root") == {
        "root.x": 1,
        "root.y.z": 2,
    }


def test_non_string_keys_are_stringified() -> None:
    assert flatten({1: "a", 2: {3: "b"}}) == {"1": "a", "2.3": "b"}


def test_custom_separator() -> None:
    assert flatten({"a": {"b": {"c": 1}}}, sep="__") == {"a__b__c": 1}


def test_scalars_pass_through_including_none_bytes_float() -> None:
    obj = {"n": None, "f": 1.5, "raw": b"\xff\x00", "s": "text"}
    assert flatten(obj) == obj


def test_empty_containers_are_kept_as_values() -> None:
    assert flatten({"a": {}, "b": [], "c": 1}) == {"a": {}, "b": [], "c": 1}


def test_top_level_list() -> None:
    assert flatten([10, 20, 30]) == {"0": 10, "1": 20, "2": 30}


def test_top_level_list_with_prefix() -> None:
    assert flatten([{"k": 1}, {"k": 2}], prefix="items") == {
        "items.0.k": 1,
        "items.1.k": 2,
    }


def test_bare_scalar_and_bare_empty_container() -> None:
    assert flatten(42) == {"": 42}
    assert flatten({}) == {"": {}}
    assert flatten([]) == {"": []}
