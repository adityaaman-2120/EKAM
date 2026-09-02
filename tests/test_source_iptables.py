"""Golden tests for ``configs/sources/iptables.yaml`` (kv engine -> OCSF 4001).

Linux netfilter kernel LOG lines: ``SRC=``/``DST=``/``PROTO=`` etc. with the
wall-clock time coming from the stripped syslog envelope. ``ULPF_WRITE_GOLDEN=1``
regenerates the golden JSON. ``time`` is excluded from the golden (the RFC 3164
stamp is yearless, so the epoch value is year-inferred) and asserted separately
against :func:`parse_timestamp`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

from ulpf.core.models import ParsedEvent
from ulpf.core.timeutil import parse_timestamp
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import load_source_definition
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.engines.util import flatten
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_HERE = Path(__file__).parent
_SOURCES = _HERE.parent / "configs" / "sources"
_SOURCE_YAML = _SOURCES / "iptables.yaml"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _definition():  # noqa: ANN202 - SourceDefinition
    return load_source_definition(yaml.safe_load(_SOURCE_YAML.read_text(encoding="utf-8")))


def _fields(sd, fixture: str) -> dict:  # noqa: ANN001
    """Parse like the coordinator does: strip the envelope, kv-parse the body, then
    merge the envelope back under ``envelope.*``."""
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    assert sd.parse.envelope == "syslog"
    envelope, message = parse_syslog_envelope(line)
    fields = dict(KvEngine().parse(message.decode("utf-8"), sd.parse.options))
    fields.update(flatten(envelope, prefix="envelope"))
    return fields


def _ocsf(fixture: str) -> dict:
    sd = _definition()
    return finalize(Mapper().to_ocsf(sd, _fields(sd, fixture), event_uid=_UID, raw_hash=_HASH))


def _check_golden(case_id: str, record: dict) -> None:
    without_time = {k: v for k, v in record.items() if k != "time"}
    path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not path.exists():
        path.write_text(json.dumps(without_time, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")
    assert without_time == json.loads(path.read_text(encoding="utf-8"))


def _parsed(fixture: str) -> ParsedEvent:
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    raw = make_raw_event(line, source_id="iptables", transport="file")
    return ParsedEvent(**raw.model_dump(), format="kv", fields=_fields(_definition(), fixture))


@pytest.mark.parametrize(
    ("case_id", "fixture", "ts"),
    [
        ("source_iptables_drop", "iptables_drop.log", "Sep  2 10:15:32"),
        ("source_iptables_accept", "iptables_accept.log", "Sep  2 10:16:04"),
        ("source_iptables_reject", "iptables_reject.log", "Sep  2 10:17:11"),
        ("source_iptables_ufw_block", "iptables_ufw_block.log", "Sep  2 10:18:45"),
    ],
)
def test_iptables_matches_golden(case_id: str, fixture: str, ts: str) -> None:
    record = _ocsf(fixture)
    _check_golden(case_id, record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True

    assert record["class_uid"] == 4001 and record["category_uid"] == 4
    assert record["activity_id"] == 6  # Traffic
    # time is year-inferred from the yearless envelope stamp -> assert dynamically
    assert record["time"] == parse_timestamp(ts)


def test_action_is_derived_from_a_key_value_log_prefix() -> None:
    drop = _ocsf("iptables_drop.log")
    accept = _ocsf("iptables_accept.log")
    reject = _ocsf("iptables_reject.log")

    assert (drop["action_id"], drop["action"], drop["disposition"]) == (2, "Denied", "Dropped")
    assert (accept["action_id"], accept["action"], accept["disposition"]) == (1, "Allowed", "Allowed")
    assert (reject["action_id"], reject["action"], reject["disposition"]) == (2, "Denied", "Dropped")
    # the `chain=`/`rule=` prefix tokens become the firewall_rule object
    assert drop["firewall_rule"] == {"uid": "90", "name": "INPUT"}


def test_bare_ufw_prefix_still_normalises_but_leaves_action_unknown() -> None:
    record = _ocsf("iptables_ufw_block.log")
    # `[UFW BLOCK]` is free text the kv engine cannot surface -> action_id defaults
    assert record["action_id"] == 0
    assert "action" not in record and "disposition" not in record
    # ...but the packet still normalises fully and validates
    assert OcsfValidator(record_metrics=False).validate(record).valid is True
    assert record["src_endpoint"] == {"ip": "203.0.113.200", "port": 6000, "interface_name": "eth0"}
    assert record["dst_endpoint"]["ip"] == "192.0.2.10" and record["dst_endpoint"]["port"] == 3389
    assert record["connection_info"] == {"protocol_name": "tcp", "protocol_num": 6}


def test_protocol_keyword_and_interface_names() -> None:
    reject = _ocsf("iptables_reject.log")  # ICMP, no ports
    assert reject["connection_info"] == {"protocol_name": "icmp", "protocol_num": 1}
    assert "port" not in reject["src_endpoint"] and "port" not in reject["dst_endpoint"]

    accept = _ocsf("iptables_accept.log")
    assert accept["src_endpoint"]["interface_name"] == "eth1"
    assert accept["dst_endpoint"]["interface_name"] == "eth0"
    assert accept["connection_info"]["protocol_num"] == 17  # UDP
    assert accept["traffic"] == {"bytes": 76}


def test_unconsumed_netfilter_and_envelope_fields_are_kept_in_unmapped() -> None:
    record = _ocsf("iptables_drop.log")
    unmapped = record["unmapped"]
    assert unmapped["TTL"] == "54"
    assert unmapped["ID"] == "54321"
    assert unmapped["MAC"].startswith("00:11:22:33:44:55")
    # the syslog envelope is preserved verbatim (requirement a)
    assert unmapped["envelope.facility_name"] == "kernel"
    assert unmapped["envelope.hostname"] == "gw"


def test_detect_routes_netfilter_lines_to_this_definition(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    for name in ("iptables", "aws_vpc_flow"):
        (directory / f"{name}.yaml").write_text((_SOURCES / f"{name}.yaml").read_text("utf-8"))
    registry = SourceRegistry()
    registry.load_all(directory)

    match = registry.match(_parsed("iptables_drop.log"))
    assert match is not None and match.name == "iptables"
    assert match.normalize.class_uid == 4001
    # an AWS VPC flow line must NOT match the iptables definition
    assert registry.match(_parsed_other("aws_vpc_flow_accept.log")).name == "aws_vpc_flow"


def _parsed_other(fixture: str) -> ParsedEvent:
    line = (_HERE / "fixtures" / fixture).read_bytes().splitlines()[0]
    raw = make_raw_event(line, source_id="aws", transport="file")
    return ParsedEvent(**raw.model_dump(), format="csv", fields={})
