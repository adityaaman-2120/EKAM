"""Tests for the additional OCSF class modules and the class registry."""

from __future__ import annotations

import pytest

from ulpf.normalize.ocsf import (
    CLASS_REGISTRY,
    base,
    detection_finding,
    dns_activity,
    http_activity,
    network_activity,
)
from ulpf.normalize.ocsf import validate as registry_validate
from ulpf.normalize.ocsf.base import build_endpoint, build_metadata, finalize

_MD = build_metadata("uid-1", "V", "P", "1.0.0", None)
_SRC = build_endpoint("192.0.2.15", 40000)
_DST = build_endpoint("203.0.113.9", 443)


# --------------------------------------------------------------------------
# registry


def test_class_registry_maps_uids_to_modules() -> None:
    assert {
        4001: network_activity,
        2004: detection_finding,
        4002: http_activity,
        4003: dns_activity,
    } == CLASS_REGISTRY
    for uid, module in CLASS_REGISTRY.items():
        assert uid == module.CLASS_UID
        assert callable(module.validate)


def test_registry_validate_dispatches_by_class_uid() -> None:
    record = finalize(
        network_activity.new_record(
            activity_id=6, severity_id=1, time=1, metadata=_MD, src_endpoint=_SRC
        )
    )
    assert registry_validate(record) == []
    assert "unknown or missing class_uid" in registry_validate({})[0]
    assert "unknown or missing class_uid" in registry_validate({"class_uid": 9999})[0]


def test_activity_id_enums_agree_with_base_activity_names() -> None:
    for uid in (4001, 4002, 4003, 2004):
        assert base.ACTIVITY_NAMES[uid] == CLASS_REGISTRY[uid].ACTIVITY_IDS


# --------------------------------------------------------------------------
# Detection Finding (2004)


def test_detection_finding_build_and_validate() -> None:
    record = finalize(
        detection_finding.new_record(
            activity_id=1,
            severity_id=3,
            time=1_700_000_000_000_000_000,
            metadata=_MD,
            finding_info=detection_finding.build_finding_info(
                uid="2100498",
                title="GPL ATTACK_RESPONSE id check returned root",
                types=["Malware"],
                analytic=detection_finding.build_analytic(name="suricata", type_id=1),
            ),
            confidence_id=2,
            risk_level_id=3,
            src_endpoint=_SRC,
            dst_endpoint=_DST,
            status_id=1,
            unmapped={"rule.created_at": "2010_09_23", "pcap_cnt": 42},
        )
    )
    assert record["class_uid"] == 2004 and record["category_uid"] == 2
    assert record["type_uid"] == 200401
    assert record["type_name"] == "Detection Finding: Create"
    assert record["confidence"] == "Medium" and record["risk_level"] == "High"
    assert record["finding_info"]["analytic"] == {"name": "suricata", "type_id": 1}
    assert record["unmapped"] == {"rule.created_at": "2010_09_23", "pcap_cnt": 42}
    assert detection_finding.validate_2004(record) == []


def test_detection_finding_validate_flags_missing_finding_info() -> None:
    record = finalize(
        detection_finding.new_record(
            activity_id=1,
            severity_id=3,
            time=1,
            metadata=_MD,
            finding_info={"uid": "x"},
        )
    )
    del record["finding_info"]
    assert "missing required attribute: finding_info" in detection_finding.validate_2004(record)


def test_detection_finding_validate_flags_bad_enums() -> None:
    record = finalize(
        detection_finding.new_record(
            activity_id=1, severity_id=1, time=1, metadata=_MD, finding_info={"uid": "x"}
        )
    )
    record["activity_id"] = 9
    record["confidence_id"] = 7
    record["risk_level_id"] = 9
    problems = detection_finding.validate_2004(record)
    assert any("activity_id 9" in p for p in problems)
    assert any("confidence_id 7" in p for p in problems)
    assert any("risk_level_id 9" in p for p in problems)


# --------------------------------------------------------------------------
# HTTP Activity (4002)


@pytest.mark.parametrize(
    ("method", "expected"),
    [("GET", 3), ("post", 6), ("PUT", 7), ("HEAD", 4), ("PATCH", 99), (None, 99)],
)
def test_activity_id_for_method(method: str | None, expected: int) -> None:
    assert http_activity.activity_id_for_method(method) == expected


def test_http_activity_build_and_validate() -> None:
    record = finalize(
        http_activity.new_record(
            activity_id=http_activity.activity_id_for_method("GET"),
            severity_id=1,
            time=1_700_000_000_000_000_000,
            metadata=_MD,
            http_request=http_activity.build_http_request(
                url=http_activity.build_url(
                    text="http://x.example/a", hostname="x.example", path="/a"
                ),
                http_method="GET",
                user_agent="curl/8",
                version="1.1",
            ),
            http_response=http_activity.build_http_response(code=200, length=1234),
            src_endpoint=_SRC,
            dst_endpoint=_DST,
            unmapped={"waf.rule_id": "942100", "waf.anomaly_score": 5},
        )
    )
    assert record["class_uid"] == 4002
    assert record["activity_id"] == 3
    assert record["type_uid"] == 400203
    assert record["type_name"] == "HTTP Activity: Get"
    assert record["http_request"]["url"]["url_string"] == "http://x.example/a"
    assert record["http_response"] == {"code": 200, "length": 1234}
    assert record["unmapped"] == {"waf.rule_id": "942100", "waf.anomaly_score": 5}
    assert http_activity.validate_4002(record) == []


def test_http_activity_validate_flags_missing_http_request() -> None:
    record = finalize(
        http_activity.new_record(
            activity_id=3,
            severity_id=1,
            time=1,
            metadata=_MD,
            http_request={"http_method": "GET"},
            src_endpoint=_SRC,
        )
    )
    del record["http_request"]
    assert "missing required attribute: http_request" in http_activity.validate_4002(record)


# --------------------------------------------------------------------------
# DNS Activity (4003)


def test_dns_activity_build_and_validate() -> None:
    record = finalize(
        dns_activity.new_record(
            activity_id=2,
            severity_id=1,
            time=1_700_000_000_000_000_000,
            metadata=_MD,
            query=dns_activity.build_query(hostname="example.com", type_="A", class_="IN"),
            src_endpoint=_SRC,
            dst_endpoint=_DST,
            answers=[dns_activity.build_answer(rdata="203.0.113.9", type_="A", ttl=300)],
            rcode_id=0,
            response_time=12,
            unmapped={"edns.do": True, "edns.udp_size": 4096},
        )
    )
    assert record["class_uid"] == 4003
    assert record["activity_id"] == 2
    assert record["type_uid"] == 400302
    assert record["type_name"] == "DNS Activity: Response"
    assert record["query"] == {"hostname": "example.com", "type": "A", "class": "IN"}
    assert record["rcode"] == "NoError"
    assert record["answers"][0] == {"rdata": "203.0.113.9", "type": "A", "ttl": 300}
    assert record["unmapped"] == {"edns.do": True, "edns.udp_size": 4096}
    assert dns_activity.validate_4003(record) == []


def test_dns_activity_validate_flags_missing_query_and_bad_rcode() -> None:
    record = finalize(
        dns_activity.new_record(
            activity_id=1,
            severity_id=1,
            time=1,
            metadata=_MD,
            query={"hostname": "x"},
            src_endpoint=_SRC,
        )
    )
    del record["query"]
    record["rcode_id"] = 42
    problems = dns_activity.validate_4003(record)
    assert "missing required attribute: query" in problems
    assert any("rcode_id 42" in p for p in problems)


def test_each_module_defines_the_common_surface() -> None:
    for module in (network_activity, detection_finding, http_activity, dns_activity):
        assert isinstance(module.CLASS_UID, int)
        assert isinstance(module.CATEGORY_UID, int)
        assert isinstance(module.ACTIVITY_IDS, dict)
        assert isinstance(module.CLASS_SHAPE, dict)
        assert callable(module.new_record)
        assert callable(module.validate)
