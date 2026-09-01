"""Tests for :mod:`ulpf.parse.engines.cef_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.engines.cef_engine import CefEngine
from ulpf.parse.registry import registry


def _parse(line: str) -> dict[str, str]:
    return CefEngine().parse(line, {})


def test_canonical_example() -> None:
    line = (
        "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|"
        "src=10.0.0.1 dst=2.1.2.2 spt=1232"
    )
    assert _parse(line) == {
        "CEFVersion": "0",
        "deviceVendor": "Security",
        "deviceProduct": "threatmanager",
        "deviceVersion": "1.0",
        "deviceEventClassId": "100",
        "name": "worm successfully stopped",
        "severity": "10",
        "src": "10.0.0.1",
        "dst": "2.1.2.2",
        "spt": "1232",
    }


def test_header_with_escaped_pipe_and_backslash() -> None:
    line = r"CEF:0|Sec\\urity|threat\|manager|1.0|100|a \| appeared|10|src=10.0.0.1"
    result = _parse(line)
    assert result["deviceVendor"] == "Sec\\urity"
    assert result["deviceProduct"] == "threat|manager"
    assert result["name"] == "a | appeared"
    assert result["src"] == "10.0.0.1"


def test_extension_value_with_escaped_equals() -> None:
    line = r"CEF:0|V|P|1.0|1|n|5|act=blocked query=user\=admin\=true dst=1.2.3.4"
    result = _parse(line)
    assert result["act"] == "blocked"
    assert result["query"] == "user=admin=true"
    assert result["dst"] == "1.2.3.4"


def test_extension_value_containing_spaces() -> None:
    line = "CEF:0|V|P|1.0|1|n|5|msg=this is a long human readable message src=10.0.0.1 spt=443"
    result = _parse(line)
    assert result["msg"] == "this is a long human readable message"
    assert result["src"] == "10.0.0.1"
    assert result["spt"] == "443"


def test_pipe_in_extension_is_literal() -> None:
    line = "CEF:0|V|P|1.0|1|n|5|msg=a|b|c src=1.1.1.1"
    result = _parse(line)
    assert result["msg"] == "a|b|c"
    assert result["src"] == "1.1.1.1"


def test_extension_escaped_newline_carriage_return_and_backslash() -> None:
    line = r"CEF:0|V|P|1.0|1|n|5|msg=line one\nline two\rend path=C:\\Windows\\Temp"
    result = _parse(line)
    assert result["msg"] == "line one\nline two\rend"
    assert result["path"] == "C:\\Windows\\Temp"


def test_custom_label_pair_expansion() -> None:
    line = (
        "CEF:0|V|P|1.0|1|n|5|cs1Label=Reason cs1=Blocked by policy "
        "cn1Label=Count cn1=42 deviceCustomDate1Label=Detected deviceCustomDate1=1620000000"
    )
    result = _parse(line)
    # originals are kept
    assert result["cs1Label"] == "Reason"
    assert result["cs1"] == "Blocked by policy"
    assert result["cn1Label"] == "Count"
    assert result["cn1"] == "42"
    # ... and the human-readable fields are emitted
    assert result["Reason"] == "Blocked by policy"
    assert result["Count"] == "42"
    assert result["Detected"] == "1620000000"


def test_custom_label_without_matching_value_is_not_expanded() -> None:
    result = _parse("CEF:0|V|P|1.0|1|n|5|cs2Label=OnlyLabel src=1.1.1.1")
    assert result["cs2Label"] == "OnlyLabel"
    assert "OnlyLabel" not in result


def test_leading_junk_token_in_extension_is_ignored() -> None:
    result = _parse("CEF:0|V|P|1.0|1|n|5|junk a=1 b=2")
    assert result["a"] == "1"
    assert result["b"] == "2"
    assert "junk" not in result


def test_header_only_no_extension() -> None:
    assert _parse("CEF:0|V|P|1.0|1|n|5|") == {
        "CEFVersion": "0",
        "deviceVendor": "V",
        "deviceProduct": "P",
        "deviceVersion": "1.0",
        "deviceEventClassId": "1",
        "name": "n",
        "severity": "5",
    }


def test_missing_cef_marker_raises() -> None:
    with pytest.raises(ParseError):
        _parse("not a cef line at all")


def test_truncated_header_raises() -> None:
    with pytest.raises(ParseError):
        _parse("CEF:0|Vendor|Product")


def test_header_with_five_segments_raises_and_does_not_parse_partially() -> None:
    # Only 5 header segments (version + 4). Must fail loudly, not return a
    # partial field dict — silent mis-parsing is what the DLQ exists to prevent.
    with pytest.raises(ParseError) as excinfo:
        _parse("CEF:0|Security|NGFW|1.0|100")
    assert excinfo.value.detail == {"found": 5, "expected": 7}


def test_syslog_prefixed_cef_is_located() -> None:
    line = "<134>Sep 19 08:26:10 fw01 CEF:0|V|P|1.0|1|n|5|src=192.0.2.1"
    result = _parse(line)
    assert result["CEFVersion"] == "0"
    assert result["src"] == "192.0.2.1"


def test_engine_is_self_registered() -> None:
    assert "cef" in registry.list_names()
    parsed = registry.get("cef").parse("CEF:0|a|b|c|d|e|f|k=v", {})
    assert parsed["deviceVendor"] == "a" and parsed["k"] == "v"
