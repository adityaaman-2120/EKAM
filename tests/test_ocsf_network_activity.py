"""Tests for :mod:`ulpf.normalize.ocsf.network_activity`."""

from __future__ import annotations

from typing import Any

from ulpf.normalize.ocsf.base import build_endpoint, build_metadata, finalize
from ulpf.normalize.ocsf.network_activity import (
    ACTION_IDS,
    ACTIVITY_IDS,
    CATEGORY_UID,
    CLASS_SHAPE,
    CLASS_UID,
    CONNECTION_INFO_KEYS,
    REQUIRED_4001,
    TRAFFIC_KEYS,
    build_connection_info,
    build_firewall_rule,
    build_traffic,
    new_record,
    validate_4001,
)


def _complete_record() -> dict[str, Any]:
    return new_record(
        activity_id=6,
        severity_id=2,
        time=1_700_000_000_000_000_000,
        metadata=build_metadata("uid-1", "Cisco", "ASA", "1.0.0", None),
        src_endpoint=build_endpoint("192.0.2.15", 51234),
        dst_endpoint=build_endpoint("203.0.113.9", 443),
        connection_info=build_connection_info(direction_id=2, protocol_name="tcp", protocol_num=6),
        traffic=build_traffic(bytes_=5060, bytes_in=1240, bytes_out=3820, packets=12),
        firewall_rule=build_firewall_rule(uid="1", name="allow-web"),
        action_id=1,
        status_id=1,
        unmapped={"nat.src_ip": "198.51.100.7", "src_zone": "trust", "dst_zone": "untrust"},
    )


def test_activity_and_action_id_enums() -> None:
    assert ACTIVITY_IDS == {
        0: "Unknown",
        1: "Open",
        2: "Close",
        3: "Reset",
        4: "Fail",
        5: "Refuse",
        6: "Traffic",
        99: "Other",
    }
    assert ACTION_IDS[1] == "Allowed"
    assert ACTION_IDS[2] == "Denied"


def test_class_shape_constants() -> None:
    assert CLASS_UID == 4001 and CATEGORY_UID == 4
    assert CLASS_SHAPE["class_uid"] == 4001
    assert CLASS_SHAPE["category_uid"] == 4
    assert "src_endpoint" in REQUIRED_4001
    assert "type_uid" in REQUIRED_4001
    for key in ("uid", "direction_id", "protocol_num", "tcp_flags", "boundary"):
        assert key in CONNECTION_INFO_KEYS
    assert TRAFFIC_KEYS == (
        "bytes",
        "bytes_in",
        "bytes_out",
        "packets",
        "packets_in",
        "packets_out",
    )


def test_new_record_then_finalize_produces_a_well_formed_event() -> None:
    record = finalize(_complete_record())
    assert record["class_uid"] == 4001
    assert record["category_uid"] == 4
    assert record["activity_id"] == 6
    assert record["activity_name"] == "Traffic"
    assert record["type_uid"] == 400106
    assert record["type_name"] == "Network Activity: Traffic"
    assert record["category_name"] == "Network Activity"
    assert record["action_id"] == 1 and record["action"] == "Allowed"
    assert record["severity"] == "Low"
    # the OCSF gaps land in unmapped, verbatim
    assert record["unmapped"] == {
        "nat.src_ip": "198.51.100.7",
        "src_zone": "trust",
        "dst_zone": "untrust",
    }
    assert validate_4001(record) == []


def test_validate_4001_passes_for_a_complete_record() -> None:
    assert validate_4001(finalize(_complete_record())) == []


def test_validate_4001_flags_missing_src_endpoint() -> None:
    record = finalize(_complete_record())
    del record["src_endpoint"]
    problems = validate_4001(record)
    assert "missing required attribute: src_endpoint" in problems


def test_validate_4001_flags_empty_src_endpoint() -> None:
    record = finalize(_complete_record())
    record["src_endpoint"] = {}
    assert "missing required attribute: src_endpoint" in validate_4001(record)


def test_validate_4001_flags_every_missing_required_attribute() -> None:
    problems = validate_4001({})
    for attr in REQUIRED_4001:
        assert f"missing required attribute: {attr}" in problems


def test_validate_4001_allows_zero_valued_scalars() -> None:
    record = finalize(
        new_record(
            activity_id=0,
            severity_id=0,
            time=1,
            metadata=build_metadata("u", "V", "P", "1", None),
            src_endpoint=build_endpoint("192.0.2.1", 1),
        )
    )
    assert validate_4001(record) == []  # activity_id 0 / severity_id 0 are valid


def test_validate_4001_rejects_wrong_class_and_bad_enums() -> None:
    record = finalize(_complete_record())
    record["class_uid"] = 1001
    record["activity_id"] = 42
    record["action_id"] = 9
    problems = validate_4001(record)
    assert any("class_uid must be 4001" in p for p in problems)
    assert any("activity_id 42" in p for p in problems)
    assert any("action_id 9" in p for p in problems)


def test_builders_strip_none() -> None:
    assert build_connection_info(protocol_name="tcp") == {"protocol_name": "tcp"}
    assert build_traffic(bytes_=100) == {"bytes": 100}
    assert build_firewall_rule(name="r1") == {"name": "r1"}
    assert build_traffic() == {}
