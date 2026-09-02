"""Golden tests for the version-keyed PAN-OS TRAFFIC source definitions.

``configs/sources/panos_traffic_v10.yaml`` and ``..._v11.yaml`` decode the same
logical event from a *differently ordered* positional CSV via version-keyed
column maps, and must produce the same OCSF 4001 record.

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
from ulpf.parse.engines.csv_engine import CsvEngine
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_HERE = Path(__file__).parent
_SOURCES = _HERE.parent / "configs" / "sources"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _definition(name: str):  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load((_SOURCES / f"{name}.yaml").read_text("utf-8")))


def _fields(sd, fixture: str) -> dict:  # noqa: ANN001
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    assert sd.parse.envelope == "syslog"
    _envelope, message = parse_syslog_envelope(line)
    return CsvEngine().parse(message.decode("utf-8"), sd.parse.options)


def _ocsf(source: str, fixture: str) -> dict:
    sd = _definition(source)
    return finalize(Mapper().to_ocsf(sd, _fields(sd, fixture), event_uid=_UID, raw_hash=_HASH))


def _check_golden(case_id: str, record: dict) -> None:
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert record == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("case_id", "source", "fixture"),
    [
        ("source_panos_traffic_v10", "panos_traffic_v10", "panos_traffic_v10.log"),
        ("source_panos_traffic_v11", "panos_traffic_v11", "panos_traffic_v11.log"),
    ],
)
def test_panos_traffic_matches_golden(case_id: str, source: str, fixture: str) -> None:
    record = _ocsf(source, fixture)
    _check_golden(case_id, record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    assert record["class_uid"] == 4001 and record["category_uid"] == 4
    assert record["activity_id"] == 6  # Traffic
    assert record["src_endpoint"] == {"ip": "192.0.2.15", "port": 51234}
    assert record["dst_endpoint"] == {"ip": "203.0.113.9", "port": 443}
    assert record["app_name"] == "ssl"
    assert record["action_id"] == 1  # allow -> Allowed
    assert record["connection_info"]["uid"] == "104512"
    assert record["connection_info"]["protocol_num"] == 6
    assert record["firewall_rule"]["name"] == "allow-web"
    assert record["traffic"]["bytes_out"] == 1240  # bytes_sent
    assert record["traffic"]["bytes_in"] == 3820  # bytes_received
    assert record["traffic"]["packets"] == 12
    # NAT + zones live in unmapped, nowhere else
    assert record["unmapped"] == {
        "nat_src_ip": "198.51.100.7",
        "nat_dst_ip": "203.0.113.9",
        "nat_src_port": "51235",
        "nat_dst_port": "443",
        "src_zone": "trust",
        "dst_zone": "untrust",
    }
    assert "198.51.100.7" not in json.dumps(
        {k: v for k, v in record.items() if k != "unmapped"}
    )


def test_v10_and_v11_produce_the_same_ocsf_record() -> None:
    assert _ocsf("panos_traffic_v10", "panos_traffic_v10.log") == _ocsf(
        "panos_traffic_v11", "panos_traffic_v11.log"
    )


def test_wrong_version_column_map_mislabels_the_row() -> None:
    """The v11 fixture decoded with the v10 map lands values in the wrong fields."""
    v10 = _definition("panos_traffic_v10")
    v11 = _definition("panos_traffic_v11")

    correct = _fields(v11, "panos_traffic_v11.log")  # v11 map on v11 row
    wrong = _fields(v10, "panos_traffic_v11.log")  # v10 map on v11 row

    assert correct["src_port"] == "51234"
    # v11 inserted tunnel_inspection_rule at index 12, shifting everything after,
    # so the v10 map reads the wrong slot for src_port (and most later fields).
    assert wrong["src_port"] != "51234"
    assert wrong["session_id"] != correct["session_id"]
