"""Tests for :mod:`ulpf.enrich.factory` — enricher assembly and health rows."""

from __future__ import annotations

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.attack_tagger import AttackTagger
from ulpf.enrich.factory import build_enrichers, describe_enrichers
from ulpf.enrich.geoip import GeoIpEnricher
from ulpf.enrich.network_context import NetworkContextEnricher
from ulpf.enrich.threat_intel import ThreatIntelEnricher


def _settings(**enrich: object) -> Settings:
    return Settings(enrich=EnrichSettings(**enrich))


def test_all_toggles_on_builds_the_full_chain_in_order() -> None:
    enrichers = build_enrichers(_settings())
    assert [type(e) for e in enrichers] == [
        NetworkContextEnricher,
        GeoIpEnricher,
        ThreatIntelEnricher,
        AttackTagger,
    ]


def test_master_switch_off_builds_nothing() -> None:
    assert build_enrichers(_settings(enabled=False)) == []


def test_individual_toggles_are_respected() -> None:
    enrichers = build_enrichers(_settings(geoip=False, attack_tagger=False))
    names = [e.name for e in enrichers]
    assert names == ["network_context", "threat_intel"]


def test_describe_enrichers_reports_every_enricher_with_status() -> None:
    settings = _settings(geoip=False)
    rows = describe_enrichers(settings, build_enrichers(settings))

    by_name = {row["name"]: row for row in rows}
    assert set(by_name) == {"network_context", "geoip", "threat_intel", "attack_tagger"}

    assert by_name["network_context"]["enabled"] is True
    assert by_name["network_context"]["ready"] is True
    assert "asset zones" in by_name["network_context"]["detail"]

    assert by_name["geoip"]["enabled"] is False  # toggled off
    assert by_name["attack_tagger"]["ready"] is True
    assert "rules" in by_name["attack_tagger"]["detail"]
    assert by_name["threat_intel"]["ready"] is True  # ships sample_ips.json


def test_describe_enrichers_when_disabled_marks_all_not_enabled() -> None:
    settings = _settings(enabled=False)
    rows = describe_enrichers(settings, build_enrichers(settings))
    assert all(row["enabled"] is False for row in rows)
    assert {row["name"] for row in rows} == {
        "network_context",
        "geoip",
        "threat_intel",
        "attack_tagger",
    }
