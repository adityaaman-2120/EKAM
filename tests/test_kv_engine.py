"""Tests for :mod:`ulpf.parse.engines.kv_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.registry import registry

_FORTIGATE = (
    'date=2019-05-10 time=11:50:48 logid="0001000014" type="traffic" '
    'subtype="local" level="notice" vd="vdom1" srcip=172.16.200.254 '
    'srcport=62024 srcintf="port11" dstip=172.16.200.2 dstport=443 proto=6 '
    'action="server-rst" policyid=0 service="HTTPS" duration=5 sentbyte=1247 '
    "rcvdbyte=1719"
)


def _engine() -> KvEngine:
    return KvEngine()


def test_fortigate_line_every_field() -> None:
    assert _engine().parse(_FORTIGATE, {}) == {
        "date": "2019-05-10",
        "time": "11:50:48",
        "logid": "0001000014",
        "type": "traffic",
        "subtype": "local",
        "level": "notice",
        "vd": "vdom1",
        "srcip": "172.16.200.254",
        "srcport": "62024",
        "srcintf": "port11",
        "dstip": "172.16.200.2",
        "dstport": "443",
        "proto": "6",
        "action": "server-rst",
        "policyid": "0",
        "service": "HTTPS",
        "duration": "5",
        "sentbyte": "1247",
        "rcvdbyte": "1719",
    }


def test_quoted_value_containing_spaces() -> None:
    result = _engine().parse('a=1 msg="hello there big world" b=2', {})
    assert result == {"a": "1", "msg": "hello there big world", "b": "2"}


def test_quoted_value_containing_equals_and_separator() -> None:
    result = _engine().parse('a=1 filter="src=10.0.0.1 and dst=10.0.0.2" b=2', {})
    assert result["filter"] == "src=10.0.0.1 and dst=10.0.0.2"
    assert result["a"] == "1" and result["b"] == "2"


def test_strip_quotes_false_keeps_the_quotes() -> None:
    result = _engine().parse('logid="0001000014" n=5', {"strip_quotes": False})
    assert result == {"logid": '"0001000014"', "n": "5"}


def test_custom_separators() -> None:
    result = _engine().parse("a:1,b:2,c:3", {"pair_separator": ",", "kv_separator": ":"})
    assert result == {"a": "1", "b": "2", "c": "3"}


def test_empty_unquoted_value_and_bare_token() -> None:
    result = _engine().parse("a= GARBAGE b=2", {})
    assert result == {"a": "", "b": "2"}  # GARBAGE has no '=' -> skipped


def test_leading_trailing_and_repeated_separators() -> None:
    assert _engine().parse("   a=1   b=2   ", {}) == {"a": "1", "b": "2"}


def test_empty_input_yields_empty_dict() -> None:
    assert _engine().parse("", {}) == {}


def test_empty_separator_option_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("a=1", {"pair_separator": ""})


def test_engine_is_self_registered() -> None:
    assert "kv" in registry.list_names()
    assert registry.get("kv").parse("x=1 y=2", {}) == {"x": "1", "y": "2"}
