"""Tests for :mod:`ulpf.parse.engines.grok_engine`."""

from __future__ import annotations

import time

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.grok_engine import GrokEngine, lint_pattern, load_pattern_file
from ulpf.parse.registry import registry

_STANDARD_PATTERNS = [
    "IPV4", "IPV6", "IP", "HOSTNAME", "WORD", "NOTSPACE", "DATA", "GREEDYDATA",
    "INT", "NUMBER", "LOGLEVEL", "TIMESTAMP_ISO8601", "SYSLOGTIMESTAMP",
    "USERNAME", "URIPATH", "QUOTEDSTRING",
]


def _engine() -> GrokEngine:
    return GrokEngine()


def test_base_library_has_every_standard_pattern() -> None:
    library = _engine()._library
    for name in _STANDARD_PATTERNS:
        assert name in library, name


def test_load_pattern_file_skips_blank_lines_and_comments(tmp_path) -> None:
    path = tmp_path / "extra.grok"
    path.write_text("# a comment\n\nFOO [a-z]+\n   \nBAR \\d+\n", encoding="utf-8")
    assert load_pattern_file(path) == {"FOO": "[a-z]+", "BAR": "\\d+"}


# --------------------------------------------------------------------------
# matching, including nested pattern resolution


def test_simple_multi_field_pattern() -> None:
    result = _engine().parse(
        "192.0.2.1 GET 200", {"pattern": "%{IPV4:client} %{WORD:method} %{NUMBER:code}"}
    )
    assert result == {"client": "192.0.2.1", "method": "GET", "code": "200"}


def test_ip_resolves_both_ipv4_and_ipv6_via_nested_alternation() -> None:
    engine = _engine()
    assert engine.parse("192.0.2.1", {"pattern": "%{IP:addr}"}) == {"addr": "192.0.2.1"}
    assert engine.parse("2001:db8::1", {"pattern": "^%{IP:addr}$"}) == {"addr": "2001:db8::1"}


def test_syslogtimestamp_and_iso8601_nested_resolution() -> None:
    engine = _engine()
    assert engine.parse("Oct 11 22:14:15", {"pattern": "%{SYSLOGTIMESTAMP:ts}"}) == {
        "ts": "Oct 11 22:14:15"
    }
    assert engine.parse("2020-01-02T03:04:05Z", {"pattern": "%{TIMESTAMP_ISO8601:ts}"}) == {
        "ts": "2020-01-02T03:04:05Z"
    }


def test_quotedstring_and_loglevel() -> None:
    engine = _engine()
    assert engine.parse('"hello world"', {"pattern": "%{QUOTEDSTRING:q}"}) == {
        "q": '"hello world"'
    }
    assert engine.parse("WARN", {"pattern": "%{LOGLEVEL:lvl}"})["lvl"] == "WARN"
    assert engine.parse("error", {"pattern": "%{LOGLEVEL:lvl}"})["lvl"] == "error"


def test_extra_patterns_option_extends_the_library() -> None:
    result = _engine().parse("abc", {"pattern": "%{FOO:f}", "patterns": {"FOO": "[a-z]+"}})
    assert result == {"f": "abc"}


def test_unmatched_optional_group_is_omitted_not_none() -> None:
    result = _engine().parse("foo", {"pattern": "%{WORD:w}(?: %{NUMBER:n})?"})
    assert result == {"w": "foo"}
    assert "n" not in result


# --------------------------------------------------------------------------
# errors


def test_unknown_pattern_reference_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("x", {"pattern": "%{NOSUCHPATTERN:x}"})


def test_no_match_raises_with_reason() -> None:
    with pytest.raises(ParseError) as exc_info:
        _engine().parse("not-an-ip-at-all", {"pattern": "^%{IPV4:x}$"})
    assert exc_info.value.detail["reason"] == "grok_no_match"


def test_unterminated_placeholder_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("x", {"pattern": "%{WORD"})


def test_missing_pattern_option_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("x", {})


def test_cyclic_or_too_deep_nesting_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("x", {"pattern": "%{A:x}", "patterns": {"A": "%{B}", "B": "%{A}"}})


# --------------------------------------------------------------------------
# the pathological-pattern timeout — the critical guarantee


def test_pathological_pattern_hits_timeout_instead_of_hanging() -> None:
    engine = _engine()
    evil_pattern = "(a|aa)+$"  # classic catastrophic-backtracking alternation
    text = "a" * 30 + "!"  # never matches -> forces exhaustive backtracking

    start = time.monotonic()
    with pytest.raises(ParseError) as exc_info:
        engine.parse(text, {"pattern": evil_pattern, "grok_timeout_ms": 150})
    elapsed = time.monotonic() - start

    assert exc_info.value.detail["reason"] == "grok_timeout"
    assert elapsed < 5.0  # bounded by the timeout, not by 2**30 backtracks


# --------------------------------------------------------------------------
# caching


def test_pattern_is_compiled_once_and_cached() -> None:
    engine = _engine()
    first = engine._get_compiled("%{WORD:w}", {})
    second = engine._get_compiled("%{WORD:w}", {})
    assert first is second


def test_different_extra_patterns_get_different_cache_entries() -> None:
    engine = _engine()
    a = engine._get_compiled("%{FOO:f}", {"FOO": "a+"})
    b = engine._get_compiled("%{FOO:f}", {"FOO": "b+"})
    assert a is not b


# --------------------------------------------------------------------------
# lint_pattern


def test_lint_flags_nested_quantifier() -> None:
    assert any("nested quantifier" in w for w in lint_pattern("(a+)+b"))
    assert any("nested quantifier" in w for w in lint_pattern("(x*)*y"))


def test_lint_flags_quantified_grok_reference() -> None:
    assert any("quantified grok reference" in w for w in lint_pattern("%{WORD:w}+"))


def test_lint_flags_unanchored_leading_greedy() -> None:
    assert any("unanchored" in w for w in lint_pattern(".*%{WORD:w}"))
    assert any("unanchored" in w for w in lint_pattern("%{GREEDYDATA:g}%{WORD:w}"))
    assert any("unanchored" in w for w in lint_pattern("%{DATA:d}%{WORD:w}"))


def test_lint_is_clean_for_a_well_formed_anchored_pattern() -> None:
    assert lint_pattern("^%{IPV4:ip} %{WORD:method} %{NUMBER:code}$") == []


# --------------------------------------------------------------------------
# self-registration


def test_engine_is_self_registered() -> None:
    assert "grok" in registry.list_names()
    assert registry.get("grok").parse("42", {"pattern": "%{NUMBER:n}"}) == {"n": "42"}
