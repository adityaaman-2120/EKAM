"""Tests for :mod:`ulpf.parse.engines.dissect_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.dissect_engine import DissectEngine, compile_pattern
from ulpf.parse.registry import registry


def _p(pattern: str, text: str, **options: object) -> dict[str, str]:
    return DissectEngine().parse(text, {"pattern": pattern, **options})


def test_normal_capture_with_literal_delimiters() -> None:
    assert _p("%{ts} %{level}: %{msg}", "2020-01-01T00:00:00 INFO: service started") == {
        "ts": "2020-01-01T00:00:00",
        "level": "INFO",
        "msg": "service started",
    }


def test_skip_placeholder_discards_the_capture() -> None:
    assert _p("%{} %{level} %{msg}", "garbage INFO hello there world") == {
        "level": "INFO",
        "msg": "hello there world",
    }


def test_leading_and_trailing_literals() -> None:
    assert _p("[%{ts}] %{msg}", "[2020-01-01] the message") == {
        "ts": "2020-01-01",
        "msg": "the message",
    }
    assert _p("%{a}-%{b};", "x-y;") == {"a": "x", "b": "y"}


def test_append_defaults_to_empty_separator() -> None:
    assert _p("%{d} %{+d} %{msg}", "2020-01-01 12:00:00 done") == {
        "d": "2020-01-0112:00:00",
        "msg": "done",
    }


def test_append_with_custom_separator_and_multiple_parts() -> None:
    assert _p("%{+n} %{+n} %{+n}", "alpha beta gamma", append_separator="-") == {
        "n": "alpha-beta-gamma"
    }
    assert _p("%{d} %{+d} %{msg}", "2020-01-01 12:00:00 done", append_separator=" ") == {
        "d": "2020-01-01 12:00:00",
        "msg": "done",
    }


def test_right_pad_collapses_repeated_delimiters() -> None:
    assert _p("%{ts->} %{level}", "2020-01-01     INFO") == {"ts": "2020-01-01", "level": "INFO"}
    # still fine with exactly one delimiter
    assert _p("%{ts->} %{level}", "2020-01-01 INFO") == {"ts": "2020-01-01", "level": "INFO"}
    # works with a non-space delimiter too
    assert _p("%{k->}=%{v}", "foo===bar") == {"k": "foo", "v": "bar"}


def test_right_pad_and_append_together() -> None:
    result = _p(
        "%{} %{ts->} %{+ts} %{level} %{msg}",
        "prefix 2020-01-01      12:00:00 WARN the rest of the line",
        append_separator=" ",
    )
    assert result == {
        "ts": "2020-01-01 12:00:00",
        "level": "WARN",
        "msg": "the rest of the line",
    }


def test_single_placeholder_captures_everything() -> None:
    assert _p("%{all}", "the whole line verbatim") == {"all": "the whole line verbatim"}


# --------------------------------------------------------------------------
# mismatch -> ParseError at scan time


def test_prefix_mismatch_raises() -> None:
    with pytest.raises(ParseError):
        _p("PFX %{a}", "NOPE a")


def test_missing_delimiter_raises() -> None:
    with pytest.raises(ParseError):
        _p("%{a}|%{b}", "no separator present")


def test_missing_trailing_literal_raises() -> None:
    with pytest.raises(ParseError):
        _p("%{a}-%{b};", "x-y")  # no trailing ';'


# --------------------------------------------------------------------------
# compile-time errors


@pytest.mark.parametrize(
    "pattern",
    [
        "no placeholders here",
        "%{a}%{b} %{c}",   # adjacent placeholders, no delimiter
        "%{a} %{b}%{c}",   # empty delimiter on a non-last field
        "%{a",             # unterminated
        "%{+} %{b}",       # append with no field name
    ],
)
def test_compile_errors(pattern: str) -> None:
    with pytest.raises(ParseError):
        compile_pattern(pattern)


def test_missing_pattern_option_raises() -> None:
    with pytest.raises(ParseError):
        DissectEngine().parse("anything", {})


# --------------------------------------------------------------------------
# compiled-once + registration


def test_pattern_is_compiled_once_and_cached() -> None:
    assert compile_pattern("%{a} %{b}") is compile_pattern("%{a} %{b}")


def test_engine_is_self_registered() -> None:
    assert "dissect" in registry.list_names()
    assert registry.get("dissect").parse("a=b", {"pattern": "%{k}=%{v}"}) == {"k": "a", "v": "b"}
