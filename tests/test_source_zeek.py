"""Golden tests for the three Zeek JSON-mode source definitions.

conn.log -> 4001, dns.log -> 4003, http.log -> 4002. ``ULPF_WRITE_GOLDEN=1``
regenerates the golden JSON.
"""

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
    raw = make_raw_event(_line(fixture).encode("utf-8"), source_id="zeek", transport="file")
    return ParsedEvent(**raw.model_dump(), format="json", fields=JsonEngine().parse(_line(fixture), {}))


def test_detect_rules_route_each_zeek_log_to_its_own_definition(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    for name in ("zeek_conn", "zeek_dns", "zeek_http"):
        (directory / f"{name}.yaml").write_text((_SOURCES / f"{name}.yaml").read_text("utf-8"))
    registry = SourceRegistry()
    registry.load_all(directory)

    matches = {
        fx: registry.match(_parsed(fx))
        for fx in ("zeek_conn.jsonl", "zeek_dns.jsonl", "zeek_http.jsonl")
    }
    assert matches["zeek_conn.jsonl"].name == "zeek_conn"
    assert matches["zeek_dns.jsonl"].name == "zeek_dns"
    assert matches["zeek_http.jsonl"].name == "zeek_http"
    assert matches["zeek_conn.jsonl"].normalize.class_uid == 4001
    assert matches["zeek_dns.jsonl"].normalize.class_uid == 4003
    assert matches["zeek_http.jsonl"].normalize.class_uid == 4002


@pytest.mark.parametrize(
    ("case_id", "source", "fixture", "class_uid"),
    [
        ("source_zeek_conn", "zeek_conn", "zeek_conn.jsonl", 4001),
        ("source_zeek_dns", "zeek_dns", "zeek_dns.jsonl", 4003),
        ("source_zeek_http", "zeek_http", "zeek_http.jsonl", 4002),
    ],
)
def test_zeek_source_matches_golden(case_id: str, source: str, fixture: str, class_uid: int) -> None:
    record = _ocsf(source, fixture)
    _check_golden(case_id, record)
    assert OcsfValidator(record_metrics=False).validate(record).valid is True
    assert record["class_uid"] == class_uid
    assert record["src_endpoint"]["ip"] == "192.0.2.15" or record["src_endpoint"]["ip"] == "192.0.2.41"


def test_zeek_conn_state_maps_to_activity_id() -> None:
    sd = _definition("zeek_conn")
    base = _line("zeek_conn.jsonl")
    expected = {"SF": 2, "S0": 4, "REJ": 5, "RSTO": 3, "SH": 4, "OTH": 6, "S1": 1}
    for state, activity_id in expected.items():
        fields = JsonEngine().parse(base.replace('"conn_state":"SF"', f'"conn_state":"{state}"'), {})
        record = finalize(Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH))
        assert record["activity_id"] == activity_id, state


def test_zeek_conn_keeps_history_in_unmapped() -> None:
    record = _ocsf("zeek_conn", "zeek_conn.jsonl")
    assert record["unmapped"]["history"] == "ShADadFf"
    assert "history" not in json.dumps({k: v for k, v in record.items() if k != "unmapped"})


def test_zeek_dns_query_and_rcode() -> None:
    record = _ocsf("zeek_dns", "zeek_dns.jsonl")
    assert record["class_uid"] == 4003 and record["activity_id"] == 2  # Response
    assert record["query"] == {"hostname": "example.com", "type": "A", "class": "IN"}  # C_INTERNET -> IN
    assert record["rcode_id"] == 0 and record["rcode"] == "NoError"  # NOERROR -> NoError
    assert record["dst_endpoint"]["port"] == 53
    # answers are arrays of objects in OCSF; the scalar mapper leaves the
    # flattened values in unmapped
    assert record["unmapped"]["answers.0"] == "203.0.113.9"


def test_zeek_http_request_and_response() -> None:
    record = _ocsf("zeek_http", "zeek_http.jsonl")
    assert record["class_uid"] == 4002 and record["activity_id"] == 3  # GET -> Get
    assert record["type_name"] == "HTTP Activity: Get"
    assert record["http_request"]["http_method"] == "GET"
    assert record["http_request"]["url"] == {
        "hostname": "example.com",
        "path": "/index.html",
        "scheme": "http",
    }
    assert record["http_request"]["user_agent"] == "curl/8.0.1"
    assert record["http_response"] == {"code": 200, "length": 1256}
