"""Tests for :mod:`ulpf.parse.engines.json_engine`."""

from __future__ import annotations

from pathlib import Path

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.json_engine import JsonEngine
from ulpf.parse.registry import registry

_FIXTURES = Path(__file__).parent / "fixtures"


def _line(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8").splitlines()[0]


def _engine() -> JsonEngine:
    return JsonEngine()


def test_zeek_conn_line_flattens_and_preserves_types() -> None:
    result = _engine().parse(_line("zeek_conn.jsonl"), {})

    assert result["id.orig_h"] == "192.0.2.15"
    assert result["id.resp_p"] == 443
    assert isinstance(result["id.resp_p"], int)
    assert result["duration"] == 12.34
    assert isinstance(result["duration"], float)
    assert result["local_orig"] is True
    assert result["local_resp"] is False
    assert result["missed_bytes"] == 0
    assert result["tunnel_parents"] == []  # empty list kept as-is in flatten mode


def test_suricata_eve_alert_flattens_nested_objects() -> None:
    result = _engine().parse(_line("suricata_eve_alert.jsonl"), {})

    assert result["event_type"] == "alert"
    assert result["src_port"] == 40333
    assert result["alert.action"] == "blocked"
    assert result["alert.signature_id"] == 2100498
    assert isinstance(result["alert.signature_id"], int)
    assert result["alert.category"] == "Potentially Bad Traffic"
    assert result["alert.severity"] == 2
    assert result["alert.metadata.created_at.0"] == "2010_09_23"
    assert result["alert.metadata.updated_at.0"] == "2019_07_26"
    assert result["flow.pkts_toserver"] == 6
    assert result["flow.start"] == "2026-08-15T22:14:20.001000+0000"

    # every value is a scalar (or an empty container) — nothing nested survived.
    assert all(not isinstance(v, dict) for v in result.values())
    assert all(not (isinstance(v, list) and v) for v in result.values())


def test_array_mode_join_produces_comma_joined_strings() -> None:
    engine = _engine()
    text = '{"tags":["a","b","c"],"nums":[1,2,3],"nested":[{"k":1}]}'

    joined = engine.parse(text, {"array_mode": "join"})
    assert joined["tags"] == "a,b,c"
    assert joined["nums"] == "1,2,3"
    # a list containing an object cannot be joined -> still index keys
    assert joined["nested.0.k"] == 1

    flat = engine.parse(text, {})  # default flatten mode
    assert flat["tags.0"] == "a" and flat["tags.2"] == "c"
    assert flat["nums.1"] == 2


def test_array_mode_join_on_suricata_metadata() -> None:
    result = _engine().parse(_line("suricata_eve_alert.jsonl"), {"array_mode": "join"})
    assert result["alert.metadata.created_at"] == "2010_09_23"


def test_top_level_array_of_one_object_is_unwrapped() -> None:
    assert _engine().parse('[{"a": 1, "b": {"c": 2}}]', {}) == {"a": 1, "b.c": 2}


def test_top_level_array_otherwise_raises() -> None:
    engine = _engine()
    with pytest.raises(ParseError):
        engine.parse('[{"a": 1}, {"b": 2}]', {})
    with pytest.raises(ParseError):
        engine.parse("[1, 2, 3]", {})


def test_top_level_scalar_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("42", {})


def test_invalid_json_raises_parse_error() -> None:
    with pytest.raises(ParseError):
        _engine().parse("{not valid json", {})


def test_unknown_array_mode_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse('{"a": [1]}', {"array_mode": "explode"})


def test_engine_is_self_registered() -> None:
    assert "json" in registry.list_names()
    assert registry.get("json").parse('{"x": 1}', {}) == {"x": 1}
