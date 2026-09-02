"""Tests for :mod:`ulpf.detect.sniffer`."""

from __future__ import annotations

import pytest

from ulpf.detect.sniffer import Sniffer, sniff, sniff_layered

_SYSLOG_WRAPPED_CEF = (
    "<134>Sep 19 08:26:10 fw01 CEF:0|Security|NGFW|1.0|100|deny|5|src=192.0.2.1 dst=203.0.113.9"
)

# --------------------------------------------------------------------------
# sniff() — one case per branch


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("<34>Oct 11 22:14:15 host su: failed", "syslog"),
        ("<190>1 2003-10-11T22:14:15Z host app - - - hello", "syslog"),
        ("CEF:0|Security|NGFW|1.0|100|deny|5|src=192.0.2.1 dst=203.0.113.9", "cef"),
        ("Sep 19 08:26 host cef-relay: CEF:0|A|B|1|1|n|1|x=1", "cef"),
        ("LEEF:2.0|Vendor|Product|1.0|eventid|src=192.0.2.1\tdst=203.0.113.9", "leef"),
        ('{"event":"login","user":"admin","ok":true}', "json"),
        ("[1, 2, 3, 4]", "json"),
        ("\t".join(["a", "b", "c", "d"]), "tsv"),
        ("ts=1697 src=192.0.2.1 dst=203.0.113.9 action=allow", "kv"),
        (",".join(str(i) for i in range(9)), "csv"),
        ("just an ordinary sentence with nothing structured", "unknown"),
        ("{ not valid json after all", "unknown"),
        ("a,b,c", "unknown"),
        ("only=one pair=two here", "unknown"),
    ],
)
def test_sniff_each_branch(line: str, expected: str) -> None:
    assert sniff(line) == expected


# --------------------------------------------------------------------------
# ordering / precedence between overlapping signals


def test_syslog_wins_over_cef() -> None:
    assert sniff("<134>CEF:0|V|P|1|1|n|1|src=192.0.2.1") == "syslog"


def test_json_wins_over_tsv() -> None:
    line = "[\t1,\t2,\t3,\t4]"  # valid JSON and >= 3 tabs
    assert line.count("\t") >= 3
    assert sniff(line) == "json"


def test_tsv_wins_over_kv() -> None:
    line = "a=1\tb=2\tc=3\td=4"  # 3 tabs and 4 key= tokens
    assert sniff(line) == "tsv"


def test_kv_wins_over_csv() -> None:
    line = "a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9"  # 8 commas and many key=
    assert sniff(line) == "kv"


# --------------------------------------------------------------------------
# sniff_layered()


def test_layered_non_syslog_repeats_outer() -> None:
    assert sniff_layered("CEF:0|V|P|1|1|n|1|x=1") == ("cef", "cef")
    assert sniff_layered("plain text") == ("unknown", "unknown")


def test_layered_syslog_wrapping_cef() -> None:
    assert sniff_layered(_SYSLOG_WRAPPED_CEF) == ("syslog", "cef")


def test_layered_syslog_wrapping_json_rfc5424() -> None:
    line = '<190>1 2003-10-11T22:14:15Z host app - - - {"event":"login","user":"admin"}'
    assert sniff_layered(line) == ("syslog", "json")


def test_layered_syslog_wrapping_plain_text() -> None:
    line = "<34>Oct 11 22:14:15 host su: just some words"
    assert sniff_layered(line) == ("syslog", "unknown")


# --------------------------------------------------------------------------
# Sniffer cache


def test_cache_classifies_source_once() -> None:
    sniffer = Sniffer()
    assert sniffer.sniff_source("fw-1", "<34>Oct 11 22:14:15 host x: y") == "syslog"
    # a wildly different later line is ignored — the source is already classified
    assert sniffer.sniff_source("fw-1", "totally,unrelated,plain,line") == "syslog"


def test_cache_bypass_forces_fresh_detection() -> None:
    sniffer = Sniffer()
    sniffer.sniff_source("fw-1", "<34>Oct 11 22:14:15 host x: y")
    assert sniffer.sniff_source("fw-1", "a plain line", cache_bypass=True) == "unknown"
    # bypass does not overwrite the cached value
    assert sniffer.sniff_source("fw-1", "a plain line") == "syslog"


def test_cache_layered_and_clear() -> None:
    sniffer = Sniffer()
    line = "<134>Sep 19 08:26:10 fw01 CEF:0|S|N|1|1|n|1|src=192.0.2.1"
    assert sniffer.sniff_source_layered("fw-1", line) == ("syslog", "cef")
    assert sniffer.sniff_source_layered("fw-1", "nonsense") == ("syslog", "cef")  # cached
    sniffer.clear()
    assert sniffer.sniff_source_layered("fw-1", "nonsense") == ("unknown", "unknown")


def test_cache_is_lru_bounded() -> None:
    sniffer = Sniffer(maxsize=2)
    sniffer.sniff_source("a", "<1>x")
    sniffer.sniff_source("b", "<1>x")
    sniffer.sniff_source("c", "<1>x")  # evicts the least-recently-used ("a")
    assert set(sniffer._cache) == {"b", "c"}
