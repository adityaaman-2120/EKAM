"""Golden tests for ``configs/sources/fortigate_traffic.yaml`` (kv engine -> OCSF 4001).

Covers the four ``action`` outcomes accept / deny / close / server-rst.
``ULPF_WRITE_GOLDEN=1`` regenerates the golden JSON.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_HERE = Path(__file__).parent
_SOURCE_YAML = _HERE.parent / "configs" / "sources" / "fortigate_traffic.yaml"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _definition():  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load(_SOURCE_YAML.read_text(encoding="utf-8")))


def _ocsf(fixture: str) -> dict:
    sd = _definition()
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    assert sd.parse.envelope == "syslog"
    _envelope, message = parse_syslog_envelope(line)
    fields = KvEngine().parse(message.decode("utf-8"), sd.parse.options)
    return finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))


def _check_golden(case_id: str, record: dict) -> None:
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert record == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("case_id", "fixture"),
    [
        ("source_fortigate_traffic_accept", "fortigate_traffic_accept.log"),
        ("source_fortigate_traffic_deny", "fortigate_traffic_deny.log"),
        ("source_fortigate_traffic_close", "fortigate_traffic_close.log"),
        ("source_fortigate_traffic_server_rst", "fortigate_traffic_server_rst.log"),
    ],
)
def test_fortigate_traffic_matches_golden(case_id: str, fixture: str) -> None:
    record = _ocsf(fixture)
    _check_golden(case_id, record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    # invariants shared by every FortiGate traffic event
    assert record["class_uid"] == 4001 and record["category_uid"] == 4
    assert record["src_endpoint"] == {
        "ip": "192.0.2.15",
        "port": 51234,
        "interface_name": "internal1",
    }
    assert record["dst_endpoint"] == {"ip": "203.0.113.9", "port": 443, "interface_name": "wan1"}
    assert record["connection_info"]["protocol_num"] == 6  # proto=6 is the IANA number
    assert record["connection_info"]["protocol_name"] == "TCP"
    assert record["connection_info"]["uid"] == "104512"
    # multi-field date+time concatenation -> one deterministic timestamp
    assert record["time"] == 1786832055000000000
    # NAT translation stays in unmapped (OCSF 4001 has no symmetric NAT pair)
    assert record["unmapped"]["transip"] == "198.51.100.7"
    assert record["unmapped"]["trandisp"] == "snat"


def test_action_value_map_covers_every_outcome() -> None:
    accept = _ocsf("fortigate_traffic_accept.log")
    deny = _ocsf("fortigate_traffic_deny.log")
    close = _ocsf("fortigate_traffic_close.log")
    reset = _ocsf("fortigate_traffic_server_rst.log")

    assert (accept["activity_id"], accept["activity_name"]) == (1, "Open")
    assert (accept["action_id"], accept["action"]) == (1, "Allowed")

    assert (deny["action_id"], deny["action"]) == (2, "Denied")
    assert deny["disposition"] == "Blocked"
    assert deny["severity_id"] == 3  # level="warning" -> Medium

    assert (close["activity_id"], close["activity_name"]) == (2, "Close")
    assert close["action_id"] == 1

    assert (reset["activity_id"], reset["activity_name"]) == (3, "Reset")
    assert reset["disposition"] == "Reset"


def test_bytes_map_to_traffic_in_and_out() -> None:
    close = _ocsf("fortigate_traffic_close.log")
    assert close["traffic"]["bytes_out"] == 8420  # sentbyte
    assert close["traffic"]["bytes_in"] == 99120  # rcvdbyte
    assert close["traffic"]["packets_out"] == 40
    assert close["traffic"]["packets_in"] == 60
    assert close["firewall_rule"]["uid"] == "1"  # policyid
