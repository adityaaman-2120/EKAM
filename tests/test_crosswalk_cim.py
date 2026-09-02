"""Tests for the OCSF -> Splunk CIM crosswalk.

Feeds committed golden OCSF records through
:func:`ulpf.normalize.crosswalk.cim.to_cim` and asserts the flat, tagged field
set each CIM data model expects.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ulpf.normalize.crosswalk.cim import to_cim

_GOLDEN = Path(__file__).parent / "golden"


def _ocsf(name: str) -> dict[str, Any]:
    return json.loads((_GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


def _assert_no_null_values(fields: dict[str, Any]) -> None:
    assert all(value is not None for value in fields.values()), fields


# --------------------------------------------------------------------------
# 4001 Network Activity -> CIM Network Traffic


def test_network_activity_4001_maps_to_network_traffic_model() -> None:
    cim = to_cim(_ocsf("source_panos_traffic_v10"))
    _assert_no_null_values(cim)

    assert cim["tags"] == ["network", "communicate"]
    assert cim["src"] == "192.0.2.15"
    assert cim["src_port"] == 51234
    assert cim["dest"] == "203.0.113.9"
    assert cim["dest_port"] == 443
    assert cim["transport"] == "tcp"
    assert cim["action"] == "allowed"  # OCSF action_id 1 -> allowed
    assert cim["bytes_out"] == 1240
    assert cim["bytes_in"] == 3820
    assert cim["bytes"] == 1240 + 3820
    assert cim["packets"] == 12  # packets_out 7 + packets_in 5
    assert cim["rule"] == "allow-web"
    assert cim["vendor_product"] == "Palo Alto Networks PAN-OS"


def test_network_traffic_action_blocked_from_a_denied_record() -> None:
    record = _ocsf("source_panos_traffic_v10")
    record["action_id"], record["action"], record["disposition"] = 2, "Denied", "Blocked"
    assert to_cim(record)["action"] == "blocked"


def test_network_traffic_bytes_fall_back_to_total_when_no_direction_split() -> None:
    record = _ocsf("source_panos_traffic_v10")
    record["traffic"] = {"bytes": 9000, "packets": 12}
    cim = to_cim(record)
    assert cim["bytes"] == 9000
    assert "bytes_in" not in cim and "bytes_out" not in cim
    assert cim["packets"] == 12


# --------------------------------------------------------------------------
# 2004 Detection Finding -> CIM Intrusion Detection


def test_detection_finding_2004_maps_to_intrusion_detection_model() -> None:
    cim = to_cim(_ocsf("source_suricata_eve_alert"))
    _assert_no_null_values(cim)

    assert cim["tags"] == ["ids", "attack"]
    assert cim["signature"] == "GPL ATTACK_RESPONSE id check returned root"
    assert cim["signature_id"] == "2100498"
    assert cim["severity"] == "medium"  # OCSF severity "Medium" -> lowercased
    assert cim["src"] == "203.0.113.200"
    assert cim["dest"] == "192.0.2.30"
    assert cim["ids_type"] == "network"
    assert cim["vendor_product"] == "OISF Suricata"
    # Network Traffic-only fields must not leak into an IDS event
    assert "transport" not in cim and "bytes" not in cim


def test_intrusion_detection_severity_falls_back_to_severity_id() -> None:
    record = _ocsf("source_suricata_eve_alert")
    record.pop("severity", None)
    record["severity_id"] = 4
    assert to_cim(record)["severity"] == "high"


# --------------------------------------------------------------------------
# other classes


def test_unmapped_class_yields_common_fields_and_no_tags() -> None:
    cim = to_cim(_ocsf("source_zeek_dns"))  # class 4003, no CIM model here
    assert cim["tags"] == []
    assert cim["src"] == "192.0.2.15"
    assert cim["dest"] == "203.0.113.53"
    assert "signature" not in cim and "transport" not in cim
