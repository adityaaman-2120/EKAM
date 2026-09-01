"""Tests for :mod:`ulpf.parse.engines.leef_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.leef_engine import LeefEngine
from ulpf.parse.registry import registry


def _parse(line: str) -> dict[str, str]:
    return LeefEngine().parse(line, {})


def test_leef_1_0_with_tab_separated_attributes() -> None:
    line = (
        "LEEF:1.0|Lancope|StealthWatch|1.0|41|"
        "src=192.0.2.1\tdst=203.0.113.9\tsrcPort=3097\tdstPort=443\tcat=Recon"
    )
    assert _parse(line) == {
        "leefVersion": "1.0",
        "vendor": "Lancope",
        "product": "StealthWatch",
        "productVersion": "1.0",
        "eventId": "41",
        "src": "192.0.2.1",
        "dst": "203.0.113.9",
        "srcPort": "3097",
        "dstPort": "443",
        "cat": "Recon",
    }


def test_leef_2_0_with_caret_delimiter() -> None:
    line = (
        "LEEF:2.0|Vendor|Product|2.5|9000|^|"
        "src=192.0.2.1^dst=203.0.113.9^spt=1099^msg=blocked by rule 7"
    )
    result = _parse(line)
    assert result["leefVersion"] == "2.0"
    assert result["delimiter"] == "^"
    assert result["src"] == "192.0.2.1"
    assert result["spt"] == "1099"
    assert result["msg"] == "blocked by rule 7"  # spaces are not the delimiter


def test_leef_2_0_with_hex_0x09_delimiter_is_tab() -> None:
    line = "LEEF:2.0|Vendor|Product|2.5|9000|0x09|src=192.0.2.1\tdst=203.0.113.9\tusrName=jdoe"
    result = _parse(line)
    assert result["delimiter"] == "0x09"
    assert result["src"] == "192.0.2.1"
    assert result["dst"] == "203.0.113.9"
    assert result["usrName"] == "jdoe"


def test_leef_2_0_with_x09_short_hex_form() -> None:
    result = _parse("LEEF:2.0|V|P|1|1|x09|a=1\tb=2")
    assert result == {
        "leefVersion": "2.0",
        "vendor": "V",
        "product": "P",
        "productVersion": "1",
        "eventId": "1",
        "delimiter": "x09",
        "a": "1",
        "b": "2",
    }


def test_leef_2_0_hex_delimiter_resolving_to_pipe() -> None:
    # 0x7c == '|'; header split stops after the delimiter field, so attribute
    # pipes stay literal and usable as the separator.
    result = _parse("LEEF:2.0|V|P|1|1|0x7c|a=1|b=2|c=3")
    assert result["a"] == "1" and result["b"] == "2" and result["c"] == "3"


def test_syslog_header_before_leef_is_tolerated() -> None:
    line = (
        "<190>Jan 18 11:07:53 qradar-host "
        "LEEF:2.0|IBM|QRadar|7.4|12345|^|devTime=2020-01-18T11:07:53^src=10.0.0.1"
    )
    result = _parse(line)
    assert result["leefVersion"] == "2.0"
    assert result["vendor"] == "IBM"
    assert result["product"] == "QRadar"
    assert result["devTime"] == "2020-01-18T11:07:53"
    assert result["src"] == "10.0.0.1"


def test_attribute_value_containing_equals_is_split_once() -> None:
    result = _parse("LEEF:1.0|V|P|1|1|url=http://x/?a=1&b=2\tsrc=1.1.1.1")
    assert result["url"] == "http://x/?a=1&b=2"
    assert result["src"] == "1.1.1.1"


def test_header_escaped_pipe() -> None:
    result = _parse(r"LEEF:1.0|Ven\|dor|Prod|1|1|src=1.1.1.1")
    assert result["vendor"] == "Ven|dor"
    assert result["src"] == "1.1.1.1"


def test_empty_v2_delimiter_field_defaults_to_tab() -> None:
    result = _parse("LEEF:2.0|V|P|1|1||a=1\tb=2")
    assert result["delimiter"] == ""
    assert result["a"] == "1" and result["b"] == "2"


def test_missing_leef_marker_raises() -> None:
    with pytest.raises(ParseError):
        _parse("just a regular log line")


def test_incomplete_v1_header_raises() -> None:
    with pytest.raises(ParseError):
        _parse("LEEF:1.0|Vendor|Product")


def test_incomplete_v2_header_raises() -> None:
    with pytest.raises(ParseError):
        _parse("LEEF:2.0|Vendor|Product|1.0|100")  # no delimiter field


def test_bad_hex_delimiter_raises() -> None:
    with pytest.raises(ParseError):
        _parse("LEEF:2.0|V|P|1|1|0xZZ|a=1")


def test_unsupported_version_raises() -> None:
    with pytest.raises(ParseError):
        _parse("LEEF:3.0|V|P|1|1|a=1")


def test_engine_is_self_registered() -> None:
    assert "leef" in registry.list_names()
    parsed = registry.get("leef").parse("LEEF:1.0|a|b|c|d|k=v", {})
    assert parsed["vendor"] == "a" and parsed["k"] == "v"
