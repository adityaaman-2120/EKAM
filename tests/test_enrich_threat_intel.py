"""Tests for :mod:`ulpf.enrich.threat_intel` — IOC matching and hot reload."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.base import Enricher
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.threat_intel import IndicatorStore, ThreatIntelEnricher

_SYNTHETIC_IP = "192.0.2.66"  # from configs/iocs/sample_ips.json (RFC 5737)


def _write(directory: Path, name: str, payload: dict[str, Any]) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _ioc(
    ioc_type: str,
    indicators: list[str],
    *,
    source: str = "feed-a",
    confidence: Any = "high",
) -> dict[str, Any]:
    return {"type": ioc_type, "source": source, "confidence": confidence, "indicators": indicators}


def _store(directory: Path) -> IndicatorStore:
    store = IndicatorStore()
    store.load_all(directory)
    return store


def _record(src: str | None = None, dst: str | None = None, **extra: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {"class_uid": 4001}
    if src is not None:
        rec["src_endpoint"] = {"ip": src, "port": 4000}
    if dst is not None:
        rec["dst_endpoint"] = {"ip": dst, "port": 443}
    rec.update(extra)
    return rec


def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# --------------------------------------------------------------------------
# matching


def test_exact_ip_indicator_matches(tmp_path: Path) -> None:
    _write(tmp_path, "ips.json", _ioc("ip", ["192.0.2.66", "198.51.100.9"], source="demo"))
    enr = ThreatIntelEnricher(_store(tmp_path))

    out = enr.enrich(_record(src="10.0.0.1", dst="192.0.2.66"))
    assert out == {
        "threat_intel": {
            "matched": True,
            "indicator": "192.0.2.66",
            "ioc_type": "ip",
            "ioc_source": "demo",
            "confidence": "high",
            "matched_on": "dst_endpoint.ip",
        }
    }


def test_no_match_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path, "ips.json", _ioc("ip", ["192.0.2.66"]))
    assert ThreatIntelEnricher(_store(tmp_path)).enrich(_record(src="10.0.0.1", dst="10.0.0.2")) == {}


def test_cidr_indicator_matches_via_trie(tmp_path: Path) -> None:
    _write(tmp_path, "nets.json", _ioc("cidr", ["203.0.113.0/24"], source="bad-nets"))
    out = ThreatIntelEnricher(_store(tmp_path)).enrich(_record(src="203.0.113.55", dst="10.0.0.1"))
    assert out["threat_intel"]["ioc_type"] == "cidr"
    assert out["threat_intel"]["indicator"] == "203.0.113.0/24"
    assert out["threat_intel"]["matched_on"] == "src_endpoint.ip"


def test_ipv6_indicator_matches(tmp_path: Path) -> None:
    _write(tmp_path, "v6.json", _ioc("ip", ["2001:db8:dead:beef::1"]))
    out = ThreatIntelEnricher(_store(tmp_path)).enrich(_record(dst="2001:db8:dead:beef::1"))
    assert out["threat_intel"]["matched"] is True


def test_domain_indicator_matches_exact_and_parent(tmp_path: Path) -> None:
    _write(tmp_path, "dom.json", _ioc("domain", ["evil.example"], source="dns-feed"))
    enr = ThreatIntelEnricher(_store(tmp_path))

    exact = enr.enrich({"class_uid": 4003, "query": {"hostname": "evil.example"}})
    child = enr.enrich({"class_uid": 4003, "query": {"hostname": "c2.evil.example"}})
    miss = enr.enrich({"class_uid": 4003, "query": {"hostname": "good.example"}})

    assert exact["threat_intel"]["ioc_source"] == "dns-feed"
    assert child["threat_intel"]["indicator"] == "evil.example"
    assert child["threat_intel"]["matched_on"] == "query.hostname"
    assert miss == {}


def test_hash_indicator_matches_case_insensitively_and_in_fingerprints(tmp_path: Path) -> None:
    digest = "a" * 63 + "F"
    _write(tmp_path, "h.json", _ioc("hash", [digest.upper()]))
    enr = ThreatIntelEnricher(_store(tmp_path))

    by_key = enr.enrich({"class_uid": 4001, "file": {"sha256": digest.lower()}})
    by_fp = enr.enrich(
        {"class_uid": 4001, "file": {"fingerprints": [{"algorithm": "sha256", "value": digest.lower()}]}}
    )
    assert by_key["threat_intel"]["ioc_type"] == "hash"
    assert by_key["threat_intel"]["matched_on"] == "file.sha256"
    assert by_fp["threat_intel"]["matched_on"] == "file.fingerprints.0.value"


def test_ip_is_checked_before_hash(tmp_path: Path) -> None:
    _write(tmp_path, "ips.json", _ioc("ip", ["192.0.2.66"], source="ip-feed"))
    _write(tmp_path, "h.json", _ioc("hash", ["deadbeef"], source="hash-feed"))
    record = _record(dst="192.0.2.66", file={"hash": "deadbeef"})
    assert ThreatIntelEnricher(_store(tmp_path)).enrich(record)["threat_intel"]["ioc_source"] == "ip-feed"


# --------------------------------------------------------------------------
# loading / validation


def test_malformed_file_is_skipped_and_others_still_load(tmp_path: Path) -> None:
    _write(tmp_path, "good.json", _ioc("ip", ["192.0.2.66", "192.0.2.67"]))
    (tmp_path / "broken.json").write_text("{ not json", encoding="utf-8")
    _write(tmp_path, "no_indicators.json", {"type": "ip", "source": "x"})

    store = _store(tmp_path)
    assert len(store.indicators) == 2
    assert store.indicators.match_ip("192.0.2.66") is not None


def test_a_bad_indicator_rejects_the_whole_file(tmp_path: Path) -> None:
    _write(tmp_path, "ips.json", _ioc("ip", ["192.0.2.66", "definitely-not-an-ip"]))
    store = _store(tmp_path)
    assert len(store.indicators) == 0


def test_counts_reports_per_type(tmp_path: Path) -> None:
    _write(tmp_path, "a.json", _ioc("ip", ["192.0.2.1", "192.0.2.2"]))
    _write(tmp_path, "b.json", _ioc("cidr", ["10.0.0.0/8"]))
    _write(tmp_path, "c.json", _ioc("domain", ["evil.example"]))
    assert _store(tmp_path).indicators.counts() == {"ip": 2, "domain": 1, "hash": 0, "cidr": 1}


# --------------------------------------------------------------------------
# hot reload (same watchdog pattern as SourceRegistry)


def test_hot_reload_picks_up_a_new_ioc_file(tmp_path: Path) -> None:
    _write(tmp_path, "seed.json", _ioc("ip", ["192.0.2.1"]))
    store = _store(tmp_path)
    store_identity = id(store)
    reloads_before = store.reload_count
    enr = ThreatIntelEnricher(store)
    assert enr.enrich(_record(dst="198.51.100.23")) == {}

    store.start_watching()
    try:
        _write(tmp_path, "new_feed.json", _ioc("ip", ["198.51.100.23"], source="live"))
        assert _wait_for(lambda: store.indicators.match_ip("198.51.100.23") is not None), (
            "hot reload did not pick up the new IOC file"
        )
    finally:
        store.stop_watching()

    assert id(store) == store_identity
    assert store.reload_count > reloads_before
    hit = enr.enrich(_record(dst="198.51.100.23"))
    assert hit["threat_intel"]["ioc_source"] == "live"
    assert store.indicators.match_ip("192.0.2.1") is not None  # original still loaded


def test_hot_reload_drops_indicators_when_a_file_is_deleted(tmp_path: Path) -> None:
    target = _write(tmp_path, "temp_feed.json", _ioc("ip", ["203.0.113.99"]))
    store = _store(tmp_path)
    assert store.indicators.match_ip("203.0.113.99") is not None

    store.start_watching()
    try:
        target.unlink()
        assert _wait_for(lambda: store.indicators.match_ip("203.0.113.99") is None), (
            "hot reload did not drop the deleted file's indicators"
        )
    finally:
        store.stop_watching()


# --------------------------------------------------------------------------
# wiring


def test_from_settings_loads_the_shipped_synthetic_sample() -> None:
    enr = ThreatIntelEnricher.from_settings(Settings(enrich=EnrichSettings()))
    hit = enr.enrich(_record(src="10.0.0.5", dst=_SYNTHETIC_IP))
    assert hit["threat_intel"]["ioc_source"] == "ULPF-SYNTHETIC-DEMO"
    assert hit["threat_intel"]["ioc_type"] == "ip"


def test_from_settings_tolerates_a_missing_ioc_directory(tmp_path: Path) -> None:
    enr = ThreatIntelEnricher.from_settings(
        Settings(enrich=EnrichSettings(ioc_dir=tmp_path / "absent"))
    )
    assert enr.enrich(_record(dst="192.0.2.66")) == {}
    assert len(enr.store.indicators) == 0


def test_is_a_valid_enricher(tmp_path: Path) -> None:
    assert isinstance(ThreatIntelEnricher(_store(tmp_path)), Enricher)


def test_runs_end_to_end_through_the_enrichment_pipeline(tmp_path: Path) -> None:
    _write(tmp_path, "ips.json", _ioc("ip", ["192.0.2.66"]))
    enr = ThreatIntelEnricher(_store(tmp_path))
    with EnrichmentPipeline(Settings(enrich=EnrichSettings()), [enr]) as pipe:
        out = pipe.enrich(_record(src="10.0.0.1", dst="192.0.2.66"))
    assert out["enrichments"]["threat_intel"]["matched"] is True
