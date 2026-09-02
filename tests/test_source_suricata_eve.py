"""Golden tests for the Suricata EVE source pair (alert -> 2004, flow -> 4001)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from ulpf.core.models import ParsedEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.engines.json_engine import JsonEngine

_HERE = Path(__file__).parent
_SOURCES = _HERE.parent / "configs" / "sources"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64

_ALERT_FIXTURE = "suricata_eve_alert.jsonl"
_FLOW_FIXTURE = "suricata_eve_flow.jsonl"


def _line(fixture: str) -> str:
    return (_HERE / "fixtures" / fixture).read_text(encoding="utf-8").splitlines()[0]


def _definition(name: str):  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load((_SOURCES / f"{name}.yaml").read_text("utf-8")))


def _ocsf(source: str, fixture: str) -> dict:
    sd = _definition(source)
    fields = JsonEngine().parse(_line(fixture), sd.parse.options)
    return finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))


def _check_golden(case_id: str, record: dict) -> None:
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert record == json.loads(path.read_text(encoding="utf-8"))


def _parsed(fixture: str) -> ParsedEvent:
    raw_bytes = _line(fixture).encode("utf-8")
    raw = make_raw_event(raw_bytes, source_id="suricata", transport="file")
    return ParsedEvent(**raw.model_dump(), format="json", fields=JsonEngine().parse(_line(fixture), {}))


# --------------------------------------------------------------------------
# detect routing: one source, two OCSF classes


def test_field_equals_detect_routes_each_event_type_to_its_own_definition(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    for name in ("suricata_eve_alert", "suricata_eve_flow"):
        (directory / f"{name}.yaml").write_text((_SOURCES / f"{name}.yaml").read_text("utf-8"))
    registry = SourceRegistry()
    registry.load_all(directory)

    alert_match = registry.match(_parsed(_ALERT_FIXTURE))
    flow_match = registry.match(_parsed(_FLOW_FIXTURE))
    assert alert_match is not None and alert_match.name == "suricata_eve_alert"
    assert flow_match is not None and flow_match.name == "suricata_eve_flow"
    assert alert_match.normalize.class_uid == 2004
    assert flow_match.normalize.class_uid == 4001


# --------------------------------------------------------------------------
# alert -> Detection Finding (2004)


def test_alert_maps_to_detection_finding_2004() -> None:
    record = _ocsf("suricata_eve_alert", _ALERT_FIXTURE)
    _check_golden("source_suricata_eve_alert", record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    assert record["class_uid"] == 2004 and record["category_uid"] == 2  # NOT 4001
    assert record["finding_info"]["uid"] == "2100498"  # alert.signature_id
    assert record["finding_info"]["title"] == "GPL ATTACK_RESPONSE id check returned root"
    assert record["finding_info"]["types"] == "Potentially Bad Traffic"
    assert record["finding_info"]["analytic"] == {"name": "Suricata", "type": "Rule", "type_id": 1}
    # Suricata severity 2 is inverted to OCSF 3 (Medium); severity 1 would be 4 (High)
    assert record["severity_id"] == 3 and record["severity"] == "Medium"
    assert record["action_id"] == 2 and record["disposition"] == "Blocked"  # alert.action="blocked"
    assert record["src_endpoint"] == {"ip": "203.0.113.200", "port": 40333}
    assert record["dst_endpoint"] == {"ip": "192.0.2.30", "port": 445}
    # flow_id kept for correlation to flow/http/tls records
    assert record["unmapped"]["flow_id"] == 1234567890


def test_suricata_severity_1_inverts_to_high() -> None:
    sd = _definition("suricata_eve_alert")
    line = _line(_ALERT_FIXTURE).replace('"severity":2', '"severity":1')
    fields = JsonEngine().parse(line, sd.parse.options)
    record = finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))
    assert record["severity_id"] == 4 and record["severity"] == "High"


# --------------------------------------------------------------------------
# flow -> Network Activity (4001)


def test_flow_maps_to_network_activity_4001() -> None:
    record = _ocsf("suricata_eve_flow", _FLOW_FIXTURE)
    _check_golden("source_suricata_eve_flow", record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    assert record["class_uid"] == 4001 and record["category_uid"] == 4
    assert record["activity_id"] == 2  # flow.state="closed" -> Close
    assert record["src_endpoint"] == {"ip": "192.0.2.15", "port": 51234}
    assert record["dst_endpoint"] == {"ip": "203.0.113.9", "port": 443}
    assert record["app_name"] == "tls"
    assert record["connection_info"]["uid"] == "1234567890"  # flow_id
    assert record["connection_info"]["protocol_num"] == 6
    assert record["connection_info"]["tcp_flags"] == "1e"
    assert record["traffic"]["bytes_out"] == 1800  # flow.bytes_toserver
    assert record["traffic"]["bytes_in"] == 4300  # flow.bytes_toclient
    # for a flow record flow_id IS the connection identifier -> connection_info.uid
    # (consumed), whereas the alert keeps it verbatim in unmapped for correlation
    assert "flow_id" not in record["unmapped"]
    assert record["unmapped"]["flow.reason"] == "timeout"
