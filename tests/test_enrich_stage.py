"""Tests for :class:`ulpf.enrich.stage.EnrichStage`."""

from __future__ import annotations

from typing import Any

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.core.models import NormalizedEvent
from ulpf.enrich.stage import EnrichStage


def _ne(ocsf: dict[str, Any], source_type: str = "fortigate_traffic") -> NormalizedEvent:
    return NormalizedEvent(
        event_uid="01a05e52-f78a-7a0b-bc34-cf3ce4f6952a",
        raw_hash="a" * 64,
        ingest_time_ns=1,
        ocsf=ocsf,
        source_type=source_type,
        mapping_version="1.0.0",
        enrichment={},
    )


class _StubPipeline:
    def __init__(self, enrichments: dict[str, Any] | Exception) -> None:
        self._enrichments = enrichments

    def enrich(self, ocsf: dict[str, Any]) -> dict[str, Any]:
        if isinstance(self._enrichments, Exception):
            raise self._enrichments
        return {**ocsf, "enrichments": dict(self._enrichments)}


def _stage(pipeline: Any, *, enabled: bool = True) -> EnrichStage:
    return EnrichStage(Settings(enrich=EnrichSettings(enabled=enabled)), pipeline)


async def test_enrichments_land_on_the_event_and_the_ocsf_record() -> None:
    stub = _StubPipeline({"threat_intel": {"matched": True, "indicator": "10.0.0.5"}})
    event = _ne({"class_uid": 4001, "src_endpoint": {"ip": "10.0.0.5"}})

    out = await _stage(stub).process(event)

    assert out is event
    assert out.ocsf["enrichments"] == {"threat_intel": {"matched": True, "indicator": "10.0.0.5"}}
    assert out.enrichment["threat_intel"]["matched"] is True


async def test_geoip_country_is_promoted_into_src_endpoint_location() -> None:
    stub = _StubPipeline(
        {
            "geoip": {
                "8.8.8.8": {
                    "country_code": "US",
                    "city": "Mountain View",
                    "latitude": 37.4,
                    "longitude": -122.1,
                }
            }
        }
    )
    event = _ne(
        {
            "class_uid": 4001,
            "src_endpoint": {"ip": "10.0.0.5"},
            "dst_endpoint": {"ip": "8.8.8.8", "port": 443},
        }
    )

    out = await _stage(stub).process(event)

    assert out.ocsf["dst_endpoint"]["location"] == {
        "country": "US",
        "city": "Mountain View",
        "coordinates": [-122.1, 37.4],
    }
    assert "location" not in out.ocsf["src_endpoint"]  # no geoip for the private IP


async def test_direction_is_promoted_only_when_the_mapper_did_not_set_it() -> None:
    stub = _StubPipeline({"network_context": {"direction": "outbound"}})
    fresh = await _stage(stub).process(_ne({"class_uid": 4001}))
    assert fresh.ocsf["connection_info"] == {"direction_id": 2, "direction": "Outbound"}

    stub2 = _StubPipeline({"network_context": {"direction": "inbound"}})
    preset = await _stage(stub2).process(
        _ne({"class_uid": 4001, "connection_info": {"direction": "Outbound", "direction_id": 2}})
    )
    assert preset.ocsf["connection_info"]["direction"] == "Outbound"  # left untouched

    stub3 = _StubPipeline({"network_context": {"direction": "internal"}})
    internal = await _stage(stub3).process(_ne({"class_uid": 4001}))
    assert "connection_info" not in internal.ocsf  # 'internal' has no OCSF direction slot


async def test_passthrough_and_disabled_events_are_left_alone() -> None:
    stub = _StubPipeline({"threat_intel": {"matched": True}})

    passthrough = _ne({"metadata": {"uid": "x"}, "unmapped": {"a": 1}}, source_type="unknown")
    assert (await _stage(stub).process(passthrough)).ocsf == {
        "metadata": {"uid": "x"},
        "unmapped": {"a": 1},
    }

    disabled = _ne({"class_uid": 4001, "src_endpoint": {"ip": "10.0.0.5"}})
    assert "enrichments" not in (await _stage(stub, enabled=False).process(disabled)).ocsf


async def test_enricher_pipeline_failure_never_fails_the_event() -> None:
    boom = _StubPipeline(RuntimeError("enrichment exploded"))
    event = _ne({"class_uid": 4001, "src_endpoint": {"ip": "10.0.0.5"}})
    out = await _stage(boom).process(event)
    assert out is event and "enrichments" not in out.ocsf


async def test_empty_enrichments_do_not_add_a_key() -> None:
    out = await _stage(_StubPipeline({})).process(_ne({"class_uid": 4001}))
    assert "enrichments" not in out.ocsf
