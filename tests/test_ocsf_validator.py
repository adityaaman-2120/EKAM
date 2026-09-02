"""Tests for :mod:`ulpf.normalize.validator`."""

from __future__ import annotations

from typing import Any

from ulpf.core.metrics import snapshot
from ulpf.normalize.ocsf import network_activity
from ulpf.normalize.ocsf.base import build_endpoint, build_metadata, finalize
from ulpf.normalize.ocsf.network_activity import build_connection_info, build_traffic
from ulpf.normalize.validator import OcsfValidator, ValidationResult

_MD = build_metadata("uid-1", "Cisco", "ASA", "1.0.0", None)


def _minimal_4001() -> dict[str, Any]:
    return finalize(
        network_activity.new_record(
            activity_id=6,
            severity_id=1,
            time=1_700_000_000_000_000_000,
            metadata=_MD,
            src_endpoint=build_endpoint("192.0.2.15", 40000),
        )
    )


def _fuller_4001() -> dict[str, Any]:
    return finalize(
        network_activity.new_record(
            activity_id=6,
            severity_id=1,
            time=1_700_000_000_000_000_000,
            metadata=_MD,
            src_endpoint=build_endpoint("192.0.2.15", 40000),
            dst_endpoint=build_endpoint("203.0.113.9", 443),
            connection_info=build_connection_info(protocol_name="tcp", protocol_num=6),
            traffic=build_traffic(bytes_=5060, packets=12),
            action_id=1,
            status_id=1,
            unmapped={"src_zone": "trust"},
        )
    )


def _v() -> OcsfValidator:
    return OcsfValidator(record_metrics=False)


def _expected_completeness(record: dict[str, Any]) -> float:
    shape = network_activity.CLASS_SHAPE
    attrs = list(dict.fromkeys([*shape["required"], *shape["recommended"]]))

    def populated(value: Any) -> bool:
        return value is not None and not (
            isinstance(value, (str, dict, list)) and len(value) == 0
        )

    return sum(1 for a in attrs if populated(record.get(a))) / len(attrs)


# --------------------------------------------------------------------------


def test_valid_record() -> None:
    result = _v().validate(_minimal_4001())
    assert isinstance(result, ValidationResult)
    assert result.valid is True
    assert result.errors == []
    assert 0.0 < result.completeness <= 1.0


def test_missing_required_attribute() -> None:
    record = _minimal_4001()
    del record["src_endpoint"]
    result = _v().validate(record)
    assert result.valid is False
    assert "missing required attribute: src_endpoint" in result.errors


def test_wrong_category_uid() -> None:
    record = _minimal_4001()
    record["category_uid"] = 3
    result = _v().validate(record)
    assert result.valid is False
    assert any("category_uid must be 4" in e for e in result.errors)


def test_bad_ip_field() -> None:
    record = _minimal_4001()
    record["src_endpoint"]["ip"] = "999.1.2.3"
    result = _v().validate(record)
    assert result.valid is False
    assert any("invalid IP address: '999.1.2.3'" in e for e in result.errors)


def test_port_out_of_range() -> None:
    record = _minimal_4001()
    record["src_endpoint"]["port"] = 70000
    result = _v().validate(record)
    assert result.valid is False
    assert any("port out of range 0-65535" in e for e in result.errors)


def test_bad_time() -> None:
    record = _minimal_4001()
    record["time"] = -5
    assert any("time must be a positive int" in e for e in _v().validate(record).errors)
    record["time"] = "1700"  # string, not int
    assert any("time must be a positive int" in e for e in _v().validate(record).errors)


def test_type_uid_mismatch() -> None:
    record = _minimal_4001()
    record["type_uid"] = 123456
    result = _v().validate(record)
    assert result.valid is False
    assert any("type_uid 123456 should be 400106" in e for e in result.errors)


def test_unknown_class_uid() -> None:
    result = _v().validate({"class_uid": 9999})
    assert result.valid is False
    assert "unknown or missing class_uid: 9999" in result.errors[0]
    assert result.completeness == 0.0

    empty = _v().validate({})
    assert empty.valid is False and empty.completeness == 0.0


def test_completeness_computed_correctly() -> None:
    minimal = _minimal_4001()
    fuller = _fuller_4001()

    minimal_result = _v().validate(minimal)
    fuller_result = _v().validate(fuller)

    assert abs(minimal_result.completeness - _expected_completeness(minimal)) < 1e-9
    assert abs(fuller_result.completeness - _expected_completeness(fuller)) < 1e-9
    # a fuller record scores strictly higher
    assert fuller_result.completeness > minimal_result.completeness
    assert fuller_result.completeness < 1.0  # `disposition` still unpopulated


def test_warnings_for_unknown_enums_do_not_fail_validation() -> None:
    record = finalize(
        network_activity.new_record(
            activity_id=0,
            severity_id=0,
            time=1,
            metadata=_MD,
            src_endpoint=build_endpoint("192.0.2.1", 1),
        )
    )
    result = _v().validate(record)
    assert result.valid is True  # activity_id 0 / severity_id 0 are valid enum values
    assert "activity_id is 0 (Unknown)" in result.warnings
    assert "severity_id is 0 (Unknown)" in result.warnings


def test_completeness_metric_is_recorded_per_event() -> None:
    key = "ulpf_normalization_completeness_count"
    before = snapshot().get(key, 0.0)
    validator = OcsfValidator()  # record_metrics=True by default
    validator.validate(_minimal_4001())
    validator.validate(_fuller_4001())
    assert snapshot()[key] - before == 2.0
