"""``EnrichStage`` — run the enrichment chain over a normalized record.

Sits **after** :class:`~ulpf.normalize.stage.NormalizeStage` and **before**
:class:`~ulpf.normalize.stage.ValidateStage`, so any attribute an enricher
promotes into a proper OCSF slot is present when the record is validated.

For each :class:`~ulpf.core.models.NormalizedEvent` it:

1. runs :class:`~ulpf.enrich.pipeline.EnrichmentPipeline` over ``event.ocsf``
   (each enricher hard-timeout-bounded; a failing enricher is skipped);
2. stores the merged result on ``event.enrichment`` **and** under
   ``event.ocsf["enrichments"]`` (full fidelity — nothing is lost);
3. **promotes** the values OCSF has a first-class home for:
   * GeoIP -> ``src_endpoint.location`` / ``dst_endpoint.location``
     (``country`` / ``city`` / ``coordinates``);
   * an inferred inbound/outbound direction -> ``connection_info.direction`` /
     ``direction_id`` (only when the mapper did not already set it).

Enrichment is best-effort: this stage never dead-letters and never raises — a
failure here leaves the record exactly as normalized.
"""

from __future__ import annotations

import logging
from typing import Any

from ulpf.config.settings import Settings
from ulpf.core.models import NormalizedEvent
from ulpf.core.pipeline import Event
from ulpf.enrich.pipeline import EnrichmentPipeline

_log = logging.getLogger(__name__)

# network_context direction -> (OCSF direction_id, OCSF direction name)
_PROMOTABLE_DIRECTION = {"inbound": (1, "Inbound"), "outbound": (2, "Outbound")}


class EnrichStage:
    """Apply the enrichment pipeline to each normalized event (never fails it)."""

    name = "enrich"

    def __init__(self, settings: Settings, pipeline: EnrichmentPipeline | None) -> None:
        """Take the (already-built) enrichment pipeline; ``None`` = stage is a pass-through."""
        self._pipeline = pipeline
        self._enabled = pipeline is not None and settings.enrich.enabled

    async def process(self, event: Event) -> NormalizedEvent:
        """Enrich ``event`` in place and return it (unchanged on any failure)."""
        assert isinstance(event, NormalizedEvent)
        if not self._enabled or "class_uid" not in event.ocsf:
            return event  # disabled, or a pass-through record with no real OCSF body
        try:
            enrichments = self._pipeline.enrich(event.ocsf).get("enrichments") or {}  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 - enrichment must never fail the event
            _log.warning(
                "enrichment failed; emitting the record unenriched",
                extra={"event_uid": event.event_uid, "error": str(exc)},
            )
            return event

        if enrichments:
            event.ocsf["enrichments"] = enrichments
            event.enrichment = {**event.enrichment, **enrichments}
            _promote(event.ocsf, enrichments)
        return event


def promote_enrichments(ocsf: dict[str, Any], enrichments: dict[str, Any]) -> None:
    """Public entry point for :func:`_promote` (used by ``ulpf inspect``)."""
    _promote(ocsf, enrichments)


def _promote(ocsf: dict[str, Any], enrichments: dict[str, Any]) -> None:
    """Copy enrichment values into the OCSF attributes that have a real home."""
    _promote_geoip(ocsf, enrichments.get("geoip") or {})
    _promote_direction(ocsf, (enrichments.get("network_context") or {}).get("direction"))


def _promote_geoip(ocsf: dict[str, Any], geoip: dict[str, Any]) -> None:
    """GeoIP fields for the src/dst address -> ``<endpoint>.location``."""
    for role in ("src_endpoint", "dst_endpoint"):
        endpoint = ocsf.get(role)
        if not isinstance(endpoint, dict):
            continue
        fields = geoip.get(endpoint.get("ip"))
        location = _geo_location(fields) if isinstance(fields, dict) else {}
        if location:
            endpoint.setdefault("location", {}).update(location)


def _geo_location(fields: dict[str, Any]) -> dict[str, Any]:
    """Shape GeoIP fields into an OCSF ``location`` (geo_location) object."""
    location: dict[str, Any] = {}
    if fields.get("country_code"):
        location["country"] = fields["country_code"]
    if fields.get("city"):
        location["city"] = fields["city"]
    lat, lon = fields.get("latitude"), fields.get("longitude")
    if lat is not None and lon is not None:
        location["coordinates"] = [lon, lat]  # OCSF order: [longitude, latitude]
    return location


def _promote_direction(ocsf: dict[str, Any], direction: Any) -> None:
    """An inbound/outbound inference -> ``connection_info.direction`` (if unset)."""
    promoted = _PROMOTABLE_DIRECTION.get(direction) if isinstance(direction, str) else None
    if promoted is None:
        return
    conn = ocsf.get("connection_info")
    if not isinstance(conn, dict):
        conn = {}
        ocsf["connection_info"] = conn
    if not conn.get("direction"):
        conn["direction_id"], conn["direction"] = promoted
