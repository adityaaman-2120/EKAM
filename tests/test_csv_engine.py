"""Tests for :mod:`ulpf.parse.engines.csv_engine`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.parse.column_maps import get_column_map
from ulpf.parse.engines.csv_engine import CsvEngine
from ulpf.parse.registry import registry


def _engine() -> CsvEngine:
    return CsvEngine()


def test_exact_width_row() -> None:
    result = _engine().parse("1,2,3", {"columns": ["a", "b", "c"]})
    assert result == {"a": "1", "b": "2", "c": "3"}


def test_extra_columns_are_kept_under_extra_index() -> None:
    result = _engine().parse("1,2,3,4,5", {"columns": ["a", "b"]})
    assert result == {"a": "1", "b": "2", "_extra.2": "3", "_extra.3": "4", "_extra.4": "5"}
    assert "_truncated" not in result


def test_missing_columns_mark_truncated_and_stay_absent() -> None:
    result = _engine().parse("1,2", {"columns": ["a", "b", "c", "d"]})
    assert result == {"a": "1", "b": "2", "_truncated": True}
    assert "c" not in result and "d" not in result


def test_skip_empty_maps_blank_fields_to_none() -> None:
    cols = {"columns": ["a", "b", "c"]}
    assert _engine().parse("1,,3", cols) == {"a": "1", "b": None, "c": "3"}
    assert _engine().parse("1,,3", {**cols, "skip_empty": False}) == {
        "a": "1",
        "b": "",
        "c": "3",
    }


def test_quoted_field_containing_the_delimiter() -> None:
    result = _engine().parse('1,"two, and a half",3', {"columns": ["a", "b", "c"]})
    assert result == {"a": "1", "b": "two, and a half", "c": "3"}


def test_custom_delimiter() -> None:
    result = _engine().parse("1|2|3", {"columns": ["a", "b", "c"], "delimiter": "|"})
    assert result == {"a": "1", "b": "2", "c": "3"}


def test_columns_option_is_required() -> None:
    with pytest.raises(ParseError):
        _engine().parse("1,2,3", {})


def test_multichar_delimiter_raises() -> None:
    with pytest.raises(ParseError):
        _engine().parse("1,2", {"columns": ["a", "b"], "delimiter": "||"})


def test_panos_traffic_10_1_positional_mapping() -> None:
    cols = get_column_map("panos_traffic", "10.1")
    row = ",".join(str(i) for i in range(len(cols)))  # value == its own index
    result = _engine().parse(row, {"columns": cols})

    assert result["src_ip"] == str(cols.index("src_ip"))
    assert result["action"] == str(cols.index("action"))
    assert result["session_end_reason"] == str(cols.index("session_end_reason"))
    assert "_truncated" not in result
    assert not any(k.startswith("_extra.") for k in result)
    assert len(result) == len(cols)


def test_panos_10_1_map_on_an_11_0_row_captures_the_overflow() -> None:
    v10 = get_column_map("panos_traffic", "10.1")
    v11 = get_column_map("panos_traffic", "11.0")  # 4 columns wider
    row = ",".join(str(i) for i in range(len(v11)))
    result = _engine().parse(row, {"columns": v10})

    # the 4 trailing 11.0-only fields land in _extra, nothing is dropped
    assert result[f"_extra.{len(v10)}"] == str(len(v10))
    assert result[f"_extra.{len(v11) - 1}"] == str(len(v11) - 1)
    assert "_truncated" not in result


def test_engine_is_self_registered() -> None:
    assert "csv" in registry.list_names()
    assert registry.get("csv").parse("x,y", {"columns": ["a", "b"]}) == {"a": "x", "b": "y"}
