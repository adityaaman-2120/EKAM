"""Tests for the OCSF -> Elastic Common Schema crosswalk.

Feeds real finalized OCSF records (the committed golden files) through
:func:`ulpf.normalize.crosswalk.ecs.to_ecs` and asserts a well-formed ECS
document comes out for both a Network Activity (4001) and a Detection Finding
(2004) record.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from ulpf.normalize.crosswalk.ecs import ECS_VERSION, to_ecs

_GOLDEN = Path(__file__).parent / "golden"


def _ocsf(name: str) -> dict[str, Any]:
    return json.loads((_GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


def _iter_leaves(obj: Any, path: str = "") -> list[tuple[str, Any]]:
    """Flatten to ``(dotted_path, value)`` pairs for scalar leaves."""
    if isinstance(obj, dict):
        out: list[tuple[str, Any]] = []
        for key, value in obj.items():
            out.extend(_iter_leaves(value, f"{path}.{key}" if path else key))
        return out
    if isinstance(obj, list):
        out = []
        for index, value in enumerate(obj):
            out.extend(_iter_leaves(value, f"{path}.{index}"))
        return out
    return [(path, obj)]


def _assert_well_formed_ecs(doc: dict[str, Any]) -> None:
    """Structural checks every ECS document this crosswalk emits must satisfy."""
    leaves = _iter_leaves(doc)
    assert all(value is not None for _, value in leaves), "ECS doc must not carry null leaves"

    assert doc["ecs"]["version"] == ECS_VERSION
    stamp = doc["@timestamp"]
    assert stamp.endswith("Z")
    datetime.fromisoformat(stamp.replace("Z", "+00:00"))  # parses as ISO 8601

    event = doc["event"]
    assert isinstance(event["category"], list) and event["category"]
    assert isinstance(event["type"], list) and event["type"]
    assert isinstance(event["severity"], int)
    assert event["kind"] in {"event", "alert"}

    for dotted, value in leaves:
        if dotted.endswith(".ip") or dotted.rsplit(".", 2)[-2:] == ["related", "ip"]:
            ipaddress.ip_address(value)  # raises if not an IP
        if dotted.endswith(".port"):
            assert isinstance(value, int) and 0 <= value <= 65535


def _timestamp_ns(stamp: str) -> int:
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1_000_000_000)


# --------------------------------------------------------------------------
# 4001 Network Activity  (PAN-OS traffic: has NAT + zones in unmapped)


def test_network_activity_4001_becomes_valid_ecs() -> None:
    record = _ocsf("source_panos_traffic_v10")
    doc = to_ecs(record)
    _assert_well_formed_ecs(doc)

    assert doc["@timestamp"] == "2026-09-01T12:00:00Z"
    assert abs(_timestamp_ns(doc["@timestamp"]) - record["time"]) < 1_000

    assert doc["event"]["category"] == ["network"]
    assert doc["event"]["type"] == ["connection"]
    assert doc["event"]["kind"] == "event"
    assert doc["event"]["action"] == "Allowed"
    assert doc["event"]["severity"] == 1
    assert doc["event"]["id"] == "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"

    assert doc["source"]["ip"] == "192.0.2.15"
    assert doc["source"]["port"] == 51234
    assert doc["source"]["bytes"] == 1240  # traffic.bytes_out
    assert doc["destination"]["ip"] == "203.0.113.9"
    assert doc["destination"]["port"] == 443
    assert doc["destination"]["bytes"] == 3820  # traffic.bytes_in

    assert doc["network"]["transport"] == "tcp"
    assert doc["network"]["iana_number"] == 6
    assert doc["network"]["bytes"] == 1240 + 3820

    assert doc["rule"]["name"] == "allow-web"
    assert doc["observer"]["vendor"] == "Palo Alto Networks"
    assert doc["observer"]["product"] == "PAN-OS"


def test_4001_recovers_nat_and_zones_that_ocsf_parks_in_unmapped() -> None:
    record = _ocsf("source_panos_traffic_v10")
    assert "nat_src_ip" in record["unmapped"] and "src_zone" in record["unmapped"]  # precondition

    doc = to_ecs(record)
    # ECS has first-class fields for these; OCSF 1.5.0 Network Activity does not
    assert doc["source"]["nat"]["ip"] == "198.51.100.7"
    assert doc["source"]["nat"]["port"] == 51235
    assert doc["destination"]["nat"]["ip"] == "203.0.113.9"
    assert doc["destination"]["nat"]["port"] == 443
    assert doc["observer"]["ingress"]["zone"] == "trust"
    assert doc["observer"]["egress"]["zone"] == "untrust"


def test_4001_related_ip_holds_every_distinct_address() -> None:
    doc = to_ecs(_ocsf("source_panos_traffic_v10"))
    # src, dst, nat_src; nat_dst == dst so it dedupes to three
    assert doc["related"]["ip"] == ["192.0.2.15", "198.51.100.7", "203.0.113.9"]


# --------------------------------------------------------------------------
# 2004 Detection Finding  (Suricata EVE alert)


def test_detection_finding_2004_becomes_valid_ecs() -> None:
    record = _ocsf("source_suricata_eve_alert")
    doc = to_ecs(record)
    _assert_well_formed_ecs(doc)

    assert doc["event"]["category"] == ["intrusion_detection"]
    assert doc["event"]["type"] == ["info"]
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["action"] == "Denied"
    assert doc["event"]["severity"] == 3

    assert doc["source"]["ip"] == "203.0.113.200"
    assert doc["source"]["port"] == 40333
    assert doc["destination"]["ip"] == "192.0.2.30"
    assert doc["destination"]["port"] == 445
    # a finding has no byte counters
    assert "bytes" not in doc["source"] and "bytes" not in doc["destination"]

    # rule.* falls back to finding_info for a detection record
    assert doc["rule"]["name"] == "GPL ATTACK_RESPONSE id check returned root"
    assert doc["rule"]["id"] == "2100498"
    assert doc["rule"]["category"] == "Potentially Bad Traffic"

    assert doc["observer"]["vendor"] == "OISF"
    assert doc["related"]["ip"] == ["192.0.2.30", "203.0.113.200"]
    assert doc["@timestamp"].startswith("2026-08-15T") and doc["@timestamp"].endswith("Z")


def test_unknown_class_uid_still_yields_a_document() -> None:
    minimal = {
        "class_uid": 9999,
        "time": 1_700_000_000_000_000_000,
        "severity_id": 1,
        "src_endpoint": {"ip": "10.0.0.1"},
        "metadata": {"product": {"vendor_name": "ACME"}},
    }
    doc = to_ecs(minimal)
    assert doc["event"]["kind"] == "event"
    assert "category" not in doc["event"] and "type" not in doc["event"]
    assert doc["source"]["ip"] == "10.0.0.1"
    assert doc["related"]["ip"] == ["10.0.0.1"]
    assert doc["@timestamp"] == "2023-11-14T22:13:20Z"
