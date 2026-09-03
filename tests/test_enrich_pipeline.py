"""Tests for :class:`ulpf.enrich.pipeline.EnrichmentPipeline`.

The load-bearing cases: an enricher that **raises** and an enricher that
**hangs** must each be skipped without failing, delaying, or dropping the event.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.core.metrics import snapshot
from ulpf.enrich.pipeline import EnrichmentPipeline


def _settings(timeout_ms: int = 30) -> Settings:
    return Settings(enrich=EnrichSettings(timeout_ms=timeout_ms))


class GeoEnricher:
    name = "geo"

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        return {"geo.country": "US", "geo.asn": 64500}


class TagEnricher:
    name = "tag"

    def __init__(self, **fields: Any) -> None:
        self._fields = fields

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        return dict(self._fields)


class RaisingEnricher:
    name = "raiser"

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("reference table not loaded")


class HangingEnricher:
    """Blocks until :meth:`release` is called (30 s backstop so CI can't wedge)."""

    name = "hanger"

    def __init__(self) -> None:
        self._gate = threading.Event()
        self.started = threading.Event()

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        self.started.set()
        self._gate.wait(timeout=30)
        return {"hang.result": "should never be merged"}

    def release(self) -> None:
        self._gate.set()


class BadReturnEnricher:
    name = "bad_return"

    def enrich(self, record: dict[str, Any]) -> Any:
        return ["not", "a", "dict"]


def test_enrichers_run_in_order_and_merge_under_enrichments() -> None:
    record = {"class_uid": 4001, "src_endpoint": {"ip": "203.0.113.9"}}
    with EnrichmentPipeline(_settings(), [GeoEnricher(), TagEnricher(**{"asset.owner": "netops"})]) as p:
        out = p.enrich(record)

    assert out["enrichments"] == {
        "geo.country": "US",
        "geo.asn": 64500,
        "asset.owner": "netops",
    }
    assert out["class_uid"] == 4001
    # the input record is not mutated
    assert "enrichments" not in record


def test_last_enricher_wins_on_a_key_collision() -> None:
    with EnrichmentPipeline(_settings(), [TagEnricher(zone="dmz"), TagEnricher(zone="core")]) as p:
        out = p.enrich({})
    assert out["enrichments"]["zone"] == "core"


def test_a_raising_enricher_is_skipped_and_the_event_survives() -> None:
    chain = [GeoEnricher(), RaisingEnricher(), TagEnricher(after="ok")]
    with EnrichmentPipeline(_settings(), chain) as p:
        out = p.enrich({"class_uid": 4001})

    assert out["class_uid"] == 4001
    assert out["enrichments"] == {"geo.country": "US", "geo.asn": 64500, "after": "ok"}


def test_a_hanging_enricher_times_out_without_blocking_the_event() -> None:
    hanger = HangingEnricher()
    pipeline = EnrichmentPipeline(_settings(timeout_ms=30), [hanger, GeoEnricher()])
    try:
        start = time.perf_counter()
        out = pipeline.enrich({"class_uid": 4001})
        elapsed = time.perf_counter() - start

        assert elapsed < 1.0, f"hanging enricher blocked the event for {elapsed:.2f}s"
        assert hanger.started.is_set()  # it really did run
        # its (never-returned) fields are absent; the rest of the chain still ran
        assert out["enrichments"] == {"geo.country": "US", "geo.asn": 64500}
        assert out["class_uid"] == 4001
    finally:
        hanger.release()
        pipeline.close()


def test_hanging_and_raising_together_still_yield_the_enriched_event() -> None:
    hanger = HangingEnricher()
    chain = [RaisingEnricher(), hanger, GeoEnricher()]
    pipeline = EnrichmentPipeline(_settings(timeout_ms=30), chain)
    try:
        out = pipeline.enrich({"event": 1})
        assert out["enrichments"] == {"geo.country": "US", "geo.asn": 64500}
        assert out["event"] == 1
    finally:
        hanger.release()
        pipeline.close()


def test_non_dict_return_is_skipped() -> None:
    with EnrichmentPipeline(_settings(), [BadReturnEnricher(), GeoEnricher()]) as p:
        out = p.enrich({})
    assert out["enrichments"] == {"geo.country": "US", "geo.asn": 64500}


def test_pre_existing_enrichments_are_kept_and_extended() -> None:
    record = {"enrichments": {"seen_before": True}}
    with EnrichmentPipeline(_settings(), [GeoEnricher()]) as p:
        out = p.enrich(record)
    assert out["enrichments"] == {"seen_before": True, "geo.country": "US", "geo.asn": 64500}
    assert record["enrichments"] == {"seen_before": True}  # original untouched


def test_empty_chain_yields_the_record_with_an_enrichments_key() -> None:
    with EnrichmentPipeline(_settings(), []) as p:
        out = p.enrich({"class_uid": 4001})
    assert out == {"class_uid": 4001, "enrichments": {}}


def test_latency_is_recorded_per_enricher_including_timeouts() -> None:
    ok_key = 'ulpf_enrich_latency_seconds_count{enricher="geo"}'
    hang_key = 'ulpf_enrich_latency_seconds_count{enricher="hanger"}'
    before = snapshot()

    hanger = HangingEnricher()
    pipeline = EnrichmentPipeline(_settings(timeout_ms=20), [GeoEnricher(), hanger])
    try:
        pipeline.enrich({})
        after = snapshot()
        assert after.get(ok_key, 0.0) - before.get(ok_key, 0.0) == 1.0
        assert after.get(hang_key, 0.0) - before.get(hang_key, 0.0) == 1.0
    finally:
        hanger.release()
        pipeline.close()
