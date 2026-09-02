"""Golden test for ``configs/sources/cisco_asa.yaml`` (302013 / 302014 / 106023).

Set ``ULPF_WRITE_GOLDEN=1`` to (re)generate the golden JSON, then inspect and
commit. ``time`` is excluded from the golden (it is a year-inferred epoch value)
and asserted separately against :func:`parse_timestamp`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from ulpf.core.timeutil import parse_timestamp
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.engines.grok_engine import GrokEngine

_HERE = Path(__file__).parent
_SOURCE_YAML = _HERE.parent / "configs" / "sources" / "cisco_asa.yaml"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _definition():  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load(_SOURCE_YAML.read_text(encoding="utf-8")))


def _ocsf(fixture: str) -> dict:
    sd = _definition()
    line = (_HERE / "fixtures" / fixture).read_text(encoding="utf-8").splitlines()[0]
    fields = GrokEngine().parse(line, sd.parse.options)
    return finalize(
        Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH)
    )


def _check_golden(case_id: str, record: dict) -> None:
    without_time = {k: v for k, v in record.items() if k != "time"}
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(without_time, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert without_time == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("case_id", "fixture", "ts"),
    [
        ("source_cisco_asa_302013", "cisco_asa_302013.log", "Oct 11 22:14:15"),
        ("source_cisco_asa_302014", "cisco_asa_302014.log", "Oct 11 22:14:45"),
        ("source_cisco_asa_106023", "cisco_asa_106023.log", "Oct 11 22:15:03"),
    ],
)
def test_ocsf_output_matches_golden(case_id: str, fixture: str, ts: str) -> None:
    record = _ocsf(fixture)
    _check_golden(case_id, record)

    # `time` is year-inferred from the yearless syslog stamp -> assert dynamically
    assert record["time"] == parse_timestamp(ts)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True


def test_302013_direction_uses_keyword_not_field_position() -> None:
    record = _ocsf("cisco_asa_302013.log")
    # ASA prints "for outside:203.0.113.9 ... to inside:192.0.2.15 ...".
    # The flow is "outbound" so the SECOND (inside) endpoint is the true source.
    assert record["src_endpoint"]["ip"] == "192.0.2.15"
    assert record["dst_endpoint"]["ip"] == "203.0.113.9"
    assert record["connection_info"]["direction"] == "Outbound"
    assert record["connection_info"]["direction_id"] == 2
    # NAT translated address is NOT in src_endpoint; it is kept in unmapped
    assert record["src_endpoint"]["ip"] != "198.51.100.7"
    assert record["unmapped"]["xlate_src_ip"] == "198.51.100.7"
    # the ASA message number is the event code
    assert record["metadata"]["event_code"] == "302013"
    assert record["activity_id"] == 1  # Open


def test_302014_teardown_keeps_direction_unknown_but_consistent_endpoints() -> None:
    record = _ocsf("cisco_asa_302014.log")
    assert record["activity_id"] == 2  # Close
    assert record["metadata"]["event_code"] == "302014"
    # no direction keyword in a teardown -> Unknown, but src/dst stay consistent
    # with the Built event for the same connection
    assert record["src_endpoint"]["ip"] == "192.0.2.15"
    assert record["dst_endpoint"]["ip"] == "203.0.113.9"
    assert record["connection_info"]["direction_id"] == 0
    assert record["traffic"]["bytes"] == 5678
    assert record["unmapped"]["duration"] == "0:00:30"


def test_106023_deny_uses_labelled_src_dst_and_numeric_or_keyword_protocol() -> None:
    record = _ocsf("cisco_asa_106023.log")
    assert record["activity_id"] == 6  # Traffic
    assert record["action_id"] == 2 and record["action"] == "Denied"
    assert record["disposition"] == "Blocked"
    assert record["metadata"]["event_code"] == "106023"
    # "src outside:203.0.113.55 dst inside:192.0.2.20" is explicitly labelled
    assert record["src_endpoint"]["ip"] == "203.0.113.55"
    assert record["dst_endpoint"]["ip"] == "192.0.2.20"
    assert record["firewall_rule"]["name"] == "outside_access_in"
    # the protocol was the keyword "tcp"; a numeric "6" must resolve the same
    assert record["connection_info"]["protocol_num"] == 6
    assert record["connection_info"]["protocol_name"] == "tcp"


def test_106023_accepts_numeric_protocol_number() -> None:
    sd = _definition()
    numeric_line = (
        "<132>Oct 11 22:15:03 fw01 %ASA-4-106023: Deny 6 src outside:203.0.113.55/40001 "
        'dst inside:192.0.2.20/22 by access-group "outside_access_in" [0x0, 0x0]'
    )
    fields = GrokEngine().parse(numeric_line, sd.parse.options)
    record = finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))
    assert fields["proto"] == "6"
    assert record["connection_info"]["protocol_num"] == 6
    assert record["connection_info"]["protocol_name"] == "tcp"
