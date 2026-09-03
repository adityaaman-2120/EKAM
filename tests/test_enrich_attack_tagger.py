"""Tests for :mod:`ulpf.enrich.attack_tagger`."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
import yaml

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.attack_tagger import _BUNDLED_TECHNIQUES, AttackMap, AttackTagger
from ulpf.enrich.base import Enricher
from ulpf.enrich.pipeline import EnrichmentPipeline

_SHIPPED_MAP = Path(__file__).parent.parent / "configs" / "attack_map.yaml"


def _tagger() -> AttackTagger:
    return AttackTagger(AttackMap.from_yaml(_SHIPPED_MAP))


def _map_from(rules: list[dict[str, Any]], techniques: dict[str, Any] | None = None) -> AttackMap:
    doc: dict[str, Any] = {"rules": rules}
    if techniques is not None:
        doc["techniques"] = techniques
    return AttackMap.from_yaml(_write_tmp(doc))


def _write_tmp(doc: dict[str, Any]) -> Path:
    path = Path(_tmpdir()) / "attack_map.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


_TMP: list[str] = []


def _tmpdir() -> str:
    import tempfile

    if not _TMP:
        _TMP.append(tempfile.mkdtemp())
    return _TMP[0]


# --------------------------------------------------------------------------
# the five starter scenarios


def test_brute_force_on_ssh_and_rdp() -> None:
    for port in (22, 3389):
        out = _tagger().enrich(
            {"class_uid": 4001, "action": "Denied", "dst_endpoint": {"port": port}}
        )
        assert out == {
            "attack": {
                "technique_ids": ["T1110"],
                "technique_names": ["Brute Force"],
                "tactics": ["credential-access"],
            }
        }


def test_allowed_traffic_to_22_is_not_brute_force() -> None:
    assert (
        _tagger().enrich({"class_uid": 4001, "action": "Allowed", "dst_endpoint": {"port": 22}})
        == {}
    )


def test_port_scan_from_suricata_signature_and_category() -> None:
    by_sig = _tagger().enrich(
        {"class_uid": 2004, "finding_info": {"title": "ET SCAN Nmap Scripting Engine User-Agent"}}
    )
    by_cat = _tagger().enrich(
        {"class_uid": 2004, "finding_info": {"types": "Detection of a Network Scan"}}
    )
    assert by_sig["attack"]["technique_ids"] == ["T1046"]
    assert by_sig["attack"]["technique_names"] == ["Network Service Discovery"]
    assert by_sig["attack"]["tactics"] == ["discovery"]
    assert by_cat["attack"]["technique_ids"] == ["T1046"]


def test_c2_over_uncommon_port() -> None:
    out = _tagger().enrich({"class_uid": 4001, "action": "Allowed", "dst_endpoint": {"port": 4444}})
    assert out["attack"]["technique_ids"] == ["T1571"]
    assert out["attack"]["technique_names"] == ["Non-Standard Port"]
    assert out["attack"]["tactics"] == ["command-and-control"]


def test_exfiltration_by_large_outbound_transfer() -> None:
    big = _tagger().enrich({"class_uid": 4001, "traffic": {"bytes_out": 60_000_000}})
    assert big["attack"]["technique_ids"] == ["T1048"]
    assert big["attack"]["tactics"] == ["exfiltration"]

    # smaller, but the flow direction is known to be outbound -> lower threshold
    directional = _tagger().enrich(
        {
            "class_uid": 4001,
            "connection_info": {"direction": "Outbound"},
            "traffic": {"bytes_out": 15_000_000},
        }
    )
    assert directional["attack"]["technique_ids"] == ["T1048"]

    assert _tagger().enrich({"class_uid": 4001, "traffic": {"bytes_out": 1000}}) == {}


def test_exploit_attempts_from_suricata_category_and_signature() -> None:
    by_cat = _tagger().enrich(
        {"class_uid": 2004, "finding_info": {"types": ["Web Application Attack"]}}
    )
    by_sig = _tagger().enrich(
        {"class_uid": 2004, "finding_info": {"title": "ET WEB_SERVER Possible SQL Injection"}}
    )
    assert by_cat["attack"]["technique_ids"] == ["T1190"]
    assert by_cat["attack"]["technique_names"] == ["Exploit Public-Facing Application"]
    assert by_cat["attack"]["tactics"] == ["initial-access"]
    assert by_sig["attack"]["technique_ids"] == ["T1190"]


# --------------------------------------------------------------------------
# merging, ordering, lookup


def test_multiple_rules_merge_and_sort_deterministically() -> None:
    out = _tagger().enrich(
        {
            "class_uid": 4001,
            "action": "Denied",
            "dst_endpoint": {"port": 22},
            "finding_info": {"title": "ET SCAN Potential Nmap scan detected"},
        }
    )
    assert out["attack"]["technique_ids"] == ["T1046", "T1110"]
    assert out["attack"]["technique_names"] == ["Network Service Discovery", "Brute Force"]
    # tactics sorted in ATT&CK kill-chain order, not alphabetically
    assert out["attack"]["tactics"] == ["credential-access", "discovery"]


def test_no_rule_matches_yields_empty() -> None:
    assert _tagger().enrich({"class_uid": 4003, "query": {"hostname": "example.com"}}) == {}


def test_alert_category_from_unmapped_is_also_consulted() -> None:
    out = _tagger().enrich(
        {"class_uid": 2004, "unmapped": {"alert.category": "Web Application Attack"}}
    )
    assert out["attack"]["technique_ids"] == ["T1190"]


def test_unknown_technique_id_falls_back_to_the_id_as_its_name() -> None:
    amap = _map_from([{"id": "custom", "technique_ids": ["T9999"], "when": {"class_uid": 4001}}])
    out = AttackTagger(amap).enrich({"class_uid": 4001})
    assert out["attack"] == {
        "technique_ids": ["T9999"],
        "technique_names": ["T9999"],
        "tactics": [],
    }


def test_map_file_can_override_the_technique_lookup() -> None:
    amap = _map_from(
        [{"id": "custom", "technique_ids": ["T9999"], "when": {"class_uid": 4001}}],
        techniques={"T9999": {"name": "Bespoke Technique", "tactics": ["impact"]}},
    )
    out = AttackTagger(amap).enrich({"class_uid": 4001})
    assert out["attack"]["technique_names"] == ["Bespoke Technique"]
    assert out["attack"]["tactics"] == ["impact"]


def test_rule_level_tactics_are_merged_with_bundled_ones() -> None:
    amap = _map_from(
        [
            {
                "id": "scan-plus",
                "technique_ids": ["T1046"],
                "tactics": ["defense-evasion"],
                "when": {"class_uid": 4001},
            }
        ]
    )
    out = AttackTagger(amap).enrich({"class_uid": 4001})
    assert out["attack"]["tactics"] == ["defense-evasion", "discovery"]  # kill-chain order


def test_malformed_rule_is_skipped_others_still_load() -> None:
    amap = _map_from(
        [
            {"id": "bad", "when": {"class_uid": 4001}},  # no technique_ids
            {"id": "good", "technique_ids": ["T1046"], "when": {"class_uid": 4001}},
        ]
    )
    assert len(amap.rules) == 1
    assert AttackTagger(amap).enrich({"class_uid": 4001})["attack"]["technique_ids"] == ["T1046"]


# --------------------------------------------------------------------------
# wiring / offline guarantees


def test_shipped_map_only_references_bundled_techniques() -> None:
    amap = AttackMap.from_yaml(_SHIPPED_MAP)
    referenced = {tid for rule in amap.rules for tid in rule.technique_ids}
    assert referenced  # sanity: the file has rules
    missing = referenced - _BUNDLED_TECHNIQUES.keys()
    assert not missing, f"shipped map references techniques with no bundled name: {missing}"
    for tid in referenced:
        assert amap.techniques[tid].name  # a real, non-empty offline name


def test_from_settings_with_missing_file_is_a_noop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="ulpf.enrich.attack_tagger"):
        tagger = AttackTagger.from_settings(
            Settings(enrich=EnrichSettings(attack_map_path=tmp_path / "absent.yaml"))
        )
    assert (
        tagger.enrich({"class_uid": 4001, "action": "Denied", "dst_endpoint": {"port": 22}}) == {}
    )
    assert any("not found" in r.message for r in caplog.records)


def test_is_a_valid_enricher() -> None:
    assert isinstance(_tagger(), Enricher)


def test_runs_end_to_end_through_the_enrichment_pipeline() -> None:
    with EnrichmentPipeline(Settings(enrich=EnrichSettings()), [_tagger()]) as pipe:
        out = pipe.enrich({"class_uid": 4001, "action": "Denied", "dst_endpoint": {"port": 3389}})
    assert out["enrichments"]["attack"]["technique_ids"] == ["T1110"]
