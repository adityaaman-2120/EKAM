"""The ``GET /health`` endpoint on the HTTP-intake app carries enricher status."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.factory import build_enrichers, describe_enrichers
from ulpf.ingest.http_intake import create_intake_app


async def _sink(_event: object) -> None:  # pragma: no cover - never called by /health
    return None


def _client(settings: Settings) -> TestClient:
    enrichers = build_enrichers(settings)
    return TestClient(
        create_intake_app(settings, _sink, health=lambda: describe_enrichers(settings, enrichers))
    )


def test_health_lists_every_enricher_and_its_status() -> None:
    body = _client(Settings(enrich=EnrichSettings(geoip=False))).get("/health").json()

    assert body["status"] == "ok"
    assert body["enrichment_enabled"] is True

    names = [row["name"] for row in body["enrichers"]]
    assert names == ["network_context", "geoip", "threat_intel", "attack_tagger"]

    rows = {row["name"]: row for row in body["enrichers"]}
    assert rows["geoip"]["enabled"] is False
    assert rows["network_context"]["enabled"] is True
    assert rows["attack_tagger"]["ready"] is True
    assert all("detail" in row for row in body["enrichers"])


def test_health_reports_enrichment_disabled() -> None:
    body = _client(Settings(enrich=EnrichSettings(enabled=False))).get("/health").json()
    assert body["enrichment_enabled"] is False
    assert all(row["enabled"] is False for row in body["enrichers"])


def test_health_without_a_provider_still_answers() -> None:
    client = TestClient(create_intake_app(Settings(), _sink))
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["enrichers"] == []
