"""Tests for :mod:`ulpf.parse.engines.tsv_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.tsv_engine import TsvEngine
from ulpf.parse.registry import registry

_T = "\t"

# A real Zeek conn.log TSV snippet (RFC5737 addresses).
_ZEEK_CONN = [
    r"#separator \x09",
    _T.join(["#set_separator", ","]),
    _T.join(["#empty_field", "(empty)"]),
    _T.join(["#unset_field", "-"]),
    _T.join(["#path", "conn"]),
    _T.join(["#open", "2019-05-10-11-50-48"]),
    _T.join(
        ["#fields", "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
         "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
         "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts",
         "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"]
    ),
    _T.join(
        ["#types", "time", "string", "addr", "port", "addr", "port", "enum", "string",
         "interval", "count", "count", "string", "bool", "bool", "count", "string",
         "count", "count", "count", "count", "set[string]"]
    ),
    _T.join(
        ["1620645048.123456", "CwjjYU2Xg9jZ5J8Zwj", "192.0.2.15", "51234",
         "203.0.113.9", "443", "tcp", "ssl", "12.34", "1240", "3820", "SF", "T", "F",
         "0", "ShADadFf", "14", "1800", "12", "4300", "(empty)"]
    ),
    _T.join(
        ["1620645049.0", "CXaBc123", "198.51.100.7", "40000", "203.0.113.53", "53",
         "udp", "dns", "0.05", "60", "120", "SF", "-", "-", "0", "Dd", "1", "88", "1",
         "148", "-"]
    ),
    _T.join(
        ["1620645050.0", "CZ99", "192.0.2.20", "55000", "203.0.113.5", "22", "tcp",
         "ssh", "1.0", "100", "200", "SF", "T", "F", "0", "ShA", "3", "180", "2",
         "120", "2001:db8::1,2001:db8::2"]
    ),
]


def _events(engine: TsvEngine, lines: list[str]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in lines:
        result = engine.parse(line, {})
        if result:
            out.append(result)
    return out


def test_zeek_conn_log_snippet_with_fields_header() -> None:
    events = _events(TsvEngine(), _ZEEK_CONN)
    assert len(events) == 3

    first = events[0]
    assert first["ts"] == "1620645048.123456"
    assert first["id.orig_h"] == "192.0.2.15"
    assert first["id.resp_p"] == "443"
    assert first["proto"] == "tcp"
    assert first["conn_state"] == "SF"
    assert first["local_orig"] == "T"
    assert first["tunnel_parents"] == []  # (empty) set -> empty list

    second = events[1]
    assert second["service"] == "dns"
    assert second["local_orig"] is None  # unset "-" -> None
    assert second["local_resp"] is None
    assert second["tunnel_parents"] is None  # unset set -> None

    third = events[2]
    assert third["tunnel_parents"] == ["2001:db8::1", "2001:db8::2"]  # set split to list


def test_hash_lines_yield_no_event() -> None:
    engine = TsvEngine()
    assert engine.parse("#path\tconn", {}) == {}
    assert engine.parse("#fields\ta\tb\tc", {}) == {}
    assert engine.parse("# a bare comment", {}) == {}


def test_data_line_without_fields_header_raises() -> None:
    with pytest.raises(ParseError):
        TsvEngine().parse("a\tb\tc", {})


def test_explicit_columns_option_overrides() -> None:
    result = TsvEngine().parse("x\ty\t-", {"columns": ["a", "b", "c"]})
    assert result == {"a": "x", "b": "y", "c": None}


def test_custom_unset_and_empty_field_options() -> None:
    result = TsvEngine().parse(
        "NULL\tNONE\tkeep",
        {"columns": ["a", "b", "c"], "unset_field": "NULL", "empty_field": "NONE"},
    )
    assert result == {"a": None, "b": None, "c": "keep"}


def test_list_fields_option_and_custom_set_separator() -> None:
    result = TsvEngine().parse(
        "a|b|c\tsolo",
        {"columns": ["s", "n"], "list_fields": ["s"], "set_separator": "|"},
    )
    assert result == {"s": ["a", "b", "c"], "n": "solo"}


def test_types_line_marks_vector_columns() -> None:
    engine = TsvEngine()
    engine.parse("#fields\tid\ttags", {"stream": "x"})
    engine.parse("#types\tcount\tvector[string]", {"stream": "x"})
    assert engine.parse("7\talpha,beta", {"stream": "x"}) == {"id": "7", "tags": ["alpha", "beta"]}


def test_fields_and_types_column_count_mismatch_raises() -> None:
    # A malformed Zeek log whose #fields and #types lines disagree on column
    # count must fail loudly rather than silently truncate to the shorter list.
    engine = TsvEngine()
    engine.parse("#fields\tid\ttags\textra", {"stream": "bad"})
    with pytest.raises(ParseError) as excinfo:
        engine.parse("#types\tcount\tvector[string]", {"stream": "bad"})
    assert excinfo.value.detail == {"fields": 3, "types": 2}


def test_streams_are_isolated_by_key() -> None:
    engine = TsvEngine()
    engine.parse("#fields\ta\tb", {"stream": "s1"})
    engine.parse("#fields\tx\ty\tz", {"stream": "s2"})
    assert engine.parse("1\t2", {"stream": "s1"}) == {"a": "1", "b": "2"}
    assert engine.parse("7\t8\t9", {"stream": "s2"}) == {"x": "7", "y": "8", "z": "9"}


def test_separator_directive_changes_the_field_split() -> None:
    engine = TsvEngine()
    engine.parse("#separator |", {"stream": "s"})
    engine.parse("#fields|a|b|c", {"stream": "s"})
    assert engine.parse("1|2|3", {"stream": "s"}) == {"a": "1", "b": "2", "c": "3"}


def test_surplus_values_are_kept_under_extra() -> None:
    result = TsvEngine().parse("1\t2\t3\t4", {"columns": ["a", "b"]})
    assert result == {"a": "1", "b": "2", "_extra.2": "3", "_extra.3": "4"}


def test_engine_is_self_registered() -> None:
    assert "tsv" in registry.list_names()
