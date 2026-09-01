"""Tests for :mod:`ulpf.parse.column_maps`."""

from __future__ import annotations

import pytest

from ulpf.parse.column_maps import get_column_map, list_column_maps


def test_panos_traffic_10_1_has_expected_anchor_fields() -> None:
    cols = get_column_map("panos_traffic", "10.1")
    assert cols[7] == "src_ip"
    assert cols[8] == "dst_ip"
    assert "action" in cols
    assert "session_end_reason" in cols


def test_versions_differ_at_the_reorder_point() -> None:
    v10 = get_column_map("panos_traffic", "10.1")
    v11 = get_column_map("panos_traffic", "11.0")
    assert v10 != v11
    # 11.0 inserts a field after `rule_name` (index 11), shifting the rest.
    assert v10[12] == "src_user"
    assert v11[12] == "tunnel_inspection_rule"
    assert v11[13] == "src_user"
    # ... and appends fields at the end.
    assert len(v11) == len(v10) + 4
    assert v11[-3:] == ["link_change_count", "policy_id", "link_switches"]
    # fields before the insertion point stay aligned
    assert v10[7] == v11[7] == "src_ip"


def test_get_column_map_returns_a_copy() -> None:
    first = get_column_map("panos_traffic", "10.1")
    first.append("mutation")
    assert "mutation" not in get_column_map("panos_traffic", "10.1")


def test_unknown_product_or_version_raises() -> None:
    with pytest.raises(KeyError):
        get_column_map("panos_traffic", "9.1")
    with pytest.raises(KeyError):
        get_column_map("panos_threat", "10.1")


def test_list_column_maps() -> None:
    assert ("panos_traffic", "10.1") in list_column_maps()
    assert ("panos_traffic", "11.0") in list_column_maps()
