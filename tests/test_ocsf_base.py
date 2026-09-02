"""Tests for :mod:`ulpf.normalize.ocsf.base`."""

from __future__ import annotations

from ulpf.normalize.ocsf.base import (
    CATEGORIES,
    OCSF_VERSION,
    SEVERITY_ID,
    build_endpoint,
    build_metadata,
    finalize,
    strip_none,
    type_uid,
)


def test_ocsf_version_is_pinned() -> None:
    assert OCSF_VERSION == "1.5.0"


def test_categories_table() -> None:
    assert CATEGORIES == {
        1: "System Activity",
        2: "Findings",
        3: "Identity & Access Management",
        4: "Network Activity",
        5: "Discovery",
        6: "Application Activity",
        7: "Remediation",
        8: "Unmanned Systems",
    }


def test_severity_id_table() -> None:
    assert SEVERITY_ID[0] == "Unknown"
    assert SEVERITY_ID[1] == "Informational"
    assert SEVERITY_ID[5] == "Critical"
    assert SEVERITY_ID[6] == "Fatal"
    assert SEVERITY_ID[99] == "Other"
    assert set(SEVERITY_ID) == {0, 1, 2, 3, 4, 5, 6, 99}


def test_type_uid() -> None:
    assert type_uid(4001, 6) == 400106
    assert type_uid(4001, 0) == 400100
    assert type_uid(2004, 2) == 200402


def test_build_metadata_pins_version_and_omits_unset() -> None:
    md = build_metadata(
        event_uid="uid-1",
        product_vendor="Cisco",
        product_name="ASA",
        mapping_version="2.1.0",
        logged_time=1_700_000_000_000_000_000,
    )
    assert md == {
        "uid": "uid-1",
        "version": "1.5.0",
        "log_version": "2.1.0",
        "logged_time": 1_700_000_000_000_000_000,
        "product": {"vendor_name": "Cisco", "name": "ASA"},
    }

    sparse = build_metadata("uid-2", None, None, "1.0.0", None)
    assert sparse == {"uid": "uid-2", "version": "1.5.0", "log_version": "1.0.0", "product": {}}


def test_build_endpoint_minimal_and_full() -> None:
    assert build_endpoint("192.0.2.1", 443) == {"ip": "192.0.2.1", "port": 443}
    assert build_endpoint(
        "192.0.2.1", 443, hostname="fw01", interface="eth0", mac="00:11:22:33:44:55"
    ) == {
        "ip": "192.0.2.1",
        "port": 443,
        "hostname": "fw01",
        "interface_name": "eth0",
        "mac": "00:11:22:33:44:55",
    }
    assert build_endpoint(None, None) == {}


def test_strip_none_is_recursive() -> None:
    assert strip_none(
        {"a": None, "b": {"c": None, "d": 1}, "e": [1, None, {"f": None, "g": 2}]}
    ) == {"b": {"d": 1}, "e": [1, {"g": 2}]}


def test_finalize_fills_derived_fields_and_strips_none() -> None:
    record = {
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 6,
        "severity_id": 2,
        "src_endpoint": {"ip": "192.0.2.1", "port": None},
        "metadata": {"uid": "u", "product": {"name": "ASA", "vendor_name": None}},
    }
    out = finalize(record)
    assert out["type_uid"] == 400106
    assert out["class_name"] == "Network Activity"
    assert out["type_name"] == "Network Activity: Traffic"
    assert out["category_name"] == "Network Activity"
    assert out["severity"] == "Low"
    assert out["src_endpoint"] == {"ip": "192.0.2.1"}  # None port stripped
    assert out["metadata"]["product"] == {"name": "ASA"}  # None vendor_name stripped


def test_finalize_does_not_mutate_its_input() -> None:
    record = {"class_uid": 4001, "activity_id": 1, "x": None}
    snapshot = {"class_uid": 4001, "activity_id": 1, "x": None}
    finalize(record)
    assert record == snapshot


def test_finalize_unknown_class_still_computes_type_uid() -> None:
    out = finalize({"class_uid": 9999, "activity_id": 3})
    assert out["type_uid"] == 999903
    assert "class_name" not in out
    assert "type_name" not in out


def test_finalize_activity_without_named_enum_uses_class_name_only() -> None:
    # class 1001 is in CLASS_NAMES but has no ACTIVITY_NAMES entry
    out = finalize({"class_uid": 1001, "activity_id": 3})
    assert out["class_name"] == "File System Activity"
    assert out["type_name"] == "File System Activity"
    assert out["type_uid"] == 100103


def test_finalize_without_activity_id_sets_class_but_no_type() -> None:
    out = finalize({"class_uid": 4001, "category_uid": 4})
    assert out["class_name"] == "Network Activity"
    assert out["category_name"] == "Network Activity"
    assert "type_uid" not in out and "type_name" not in out
