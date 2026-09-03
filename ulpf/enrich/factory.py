"""Assemble the enricher chain and the :class:`EnrichmentPipeline` from settings.

One place decides *which* enrichers run, honouring ``settings.enrich``:

* ``enabled`` — master switch; when False no enrichers are built.
* ``network_context`` / ``geoip`` / ``threat_intel`` / ``attack_tagger`` — per
  enricher toggles.

The order here is the order they run: cheap pure-Python context first, then the
data-backed lookups, then the ATT&CK mapping (which can read fields the others
have not touched — it works off the raw OCSF record, like every enricher).
"""

from __future__ import annotations

from typing import Any

from ulpf.config.settings import Settings
from ulpf.enrich.attack_tagger import AttackTagger
from ulpf.enrich.base import Enricher
from ulpf.enrich.geoip import GeoIpEnricher
from ulpf.enrich.network_context import NetworkContextEnricher
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.threat_intel import ThreatIntelEnricher

# toggle attribute -> builder
_BUILDERS: tuple[tuple[str, Any], ...] = (
    ("network_context", NetworkContextEnricher.from_settings),
    ("geoip", GeoIpEnricher.from_settings),
    ("threat_intel", ThreatIntelEnricher.from_settings),
    ("attack_tagger", AttackTagger.from_settings),
)

#: Enricher names in execution order — the order the chain runs.
ENRICHER_ORDER: tuple[str, ...] = tuple(attr for attr, _ in _BUILDERS)


def build_enrichers(settings: Settings) -> list[Enricher]:
    """Return the configured enricher chain (empty when enrichment is disabled)."""
    if not settings.enrich.enabled:
        return []
    return [build(settings) for attr, build in _BUILDERS if getattr(settings.enrich, attr, False)]


def build_enrichment_pipeline(
    settings: Settings, enrichers: list[Enricher] | None = None
) -> EnrichmentPipeline:
    """Build the :class:`EnrichmentPipeline` with the configured chain."""
    return EnrichmentPipeline(settings, enrichers or build_enrichers(settings))


def describe_enrichers(settings: Settings, enrichers: list[Enricher]) -> list[dict[str, Any]]:
    """A per-enricher status list for the /health endpoint.

    Each entry: ``{"name", "enabled", "ready", "detail"}``. ``enabled`` reflects
    the config toggle; ``ready`` / ``detail`` come from the enricher's own
    ``describe()`` (when it has one).
    """
    active = {getattr(e, "name", type(e).__name__): e for e in enrichers}
    rows: list[dict[str, Any]] = []
    for attr, _ in _BUILDERS:
        toggled_on = settings.enrich.enabled and getattr(settings.enrich, attr, False)
        enricher = active.get(attr)
        described = (
            enricher.describe()
            if enricher is not None and hasattr(enricher, "describe")
            else {"ready": False, "detail": "not loaded"}
        )
        rows.append({"name": attr, "enabled": bool(toggled_on), **described})
    return rows
