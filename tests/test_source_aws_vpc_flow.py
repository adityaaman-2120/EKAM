"""Golden tests for ``configs/sources/aws_vpc_flow.yaml`` (csv engine -> OCSF 4001).

AWS VPC Flow Logs, default version-2 positional format, space-delimited. This is
ULPF's hybrid / multi-cloud path: a cloud flow export normalised into the same
OCSF 4001 shape a firewall or Zeek conn.log produces. ``ULPF_WRITE_GOLDEN=1``
regenerates the golden JSON; ``start`` is epoch seconds so the golden is fully
deterministic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from ulpf.core.errors import MappingError
from ulpf.core.models import ParsedEvent
from ulpf.core.timeutil import parse_timestamp
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.engines.csv_engine import CsvEngine

_HERE = Path(__file__).parent
_SOURCES = _HERE.parent / "configs" / "sources"
_SOURCE_YAML = _SOURCES / "aws_vpc_flow.yaml"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _definition():  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load(_SOURCE_YAML.read_text(encoding="utf-8")))


def _fields(sd, fixture: str) -> dict:  # noqa: ANN001
    line = (_HERE / "fixtures" / fixture).read_text(encoding="utf-8").splitlines()[0]
    return CsvEngine().parse(line, sd.parse.options)


def _ocsf(fixture: str) -> dict:
    sd = _definition()
    return finalize(Mapper().to_ocsf(sd, _fields(sd, fixture), event_uid=_UID, raw_hash=_HASH))


def _check_golden(case_id: str, record: dict) -> None:
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert record == json.loads(path.read_text(encoding="utf-8"))


def _parsed(fixture: str) -> ParsedEvent:
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    raw = make_raw_event(line, source_id="aws", transport="file")
    return ParsedEvent(**raw.model_dump(), format="csv", fields=_fields(_definition(), fixture))


@pytest.mark.parametrize(
    ("case_id", "fixture"),
    [
        ("source_aws_vpc_flow_accept", "aws_vpc_flow_accept.log"),
        ("source_aws_vpc_flow_reject", "aws_vpc_flow_reject.log"),
    ],
)
def test_aws_vpc_flow_matches_golden(case_id: str, fixture: str) -> None:
    record = _ocsf(fixture)
    _check_golden(case_id, record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    assert record["class_uid"] == 4001 and record["category_uid"] == 4
    assert record["activity_id"] == 6  # Traffic
    assert record["connection_info"]["protocol_num"] == 6
    assert record["connection_info"]["protocol_name"] == "tcp"
    assert record["status_id"] == 1  # log-status OK -> Success
    # epoch-seconds `start` -> deterministic UTC epoch nanoseconds
    assert record["time"] == parse_timestamp(1725278400 if "accept" in fixture else 1725278500)
    # cloud attribution stays in unmapped
    assert record["unmapped"]["account_id"] == "123456789010"
    assert record["unmapped"]["interface_id"] == "eni-0abc1234def567890"


def test_action_maps_accept_and_reject() -> None:
    accept = _ocsf("aws_vpc_flow_accept.log")
    reject = _ocsf("aws_vpc_flow_reject.log")

    assert (accept["action_id"], accept["action"], accept["disposition"]) == (1, "Allowed", "Allowed")
    assert accept["src_endpoint"] == {"ip": "192.0.2.15", "port": 51234}
    assert accept["traffic"] == {"bytes": 1240, "packets": 14}

    assert (reject["action_id"], reject["action"], reject["disposition"]) == (2, "Denied", "Blocked")
    assert reject["dst_endpoint"] == {"ip": "192.0.2.20", "port": 3389}


def test_log_status_skipdata_maps_to_failure() -> None:
    sd = _definition()
    line = (_HERE / "fixtures" / "aws_vpc_flow_accept.log").read_text("utf-8").splitlines()[0]
    fields = CsvEngine().parse(line.replace(" ACCEPT OK", " ACCEPT SKIPDATA"), sd.parse.options)
    record = finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))
    assert record["status_id"] == 2  # SKIPDATA -> Failure
    assert OcsfValidator(record_metrics=False).validate(record).valid is True


def test_nodata_line_has_no_five_tuple_and_is_dead_lettered() -> None:
    # A NODATA record carries "-" for every flow field; the required src_endpoint.ip
    # cannot be built, so the mapper raises (the NormalizeStage routes this to the
    # DLQ) rather than emitting a bogus record or dropping the line silently.
    sd = _definition()
    fields = _fields(sd, "aws_vpc_flow_nodata.log")
    assert fields["log_status"] == "NODATA"
    assert fields["srcaddr"] == "-"
    with pytest.raises(MappingError):
        Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH)


def test_detect_routes_vpc_flow_lines_to_this_definition(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    for name in ("aws_vpc_flow", "iptables"):
        (directory / f"{name}.yaml").write_text((_SOURCES / f"{name}.yaml").read_text("utf-8"))
    registry = SourceRegistry()
    registry.load_all(directory)

    match = registry.match(_parsed("aws_vpc_flow_accept.log"))
    assert match is not None and match.name == "aws_vpc_flow"
    assert match.normalize.class_uid == 4001
