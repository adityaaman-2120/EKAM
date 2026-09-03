"""Tests for :mod:`ulpf.enrich.network_context` (pure-Python, air-gap-safe)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.base import Enricher
from ulpf.enrich.network_context import NetworkContextEnricher, ZoneMap
from ulpf.enrich.pipeline import EnrichmentPipeline

_ASSETS = Path(__file__).parent.parent / "configs" / "assets.yaml"


def _enricher(assets: Path | None = None) -> NetworkContextEnricher:
    return NetworkContextEnricher(ZoneMap.from_yaml(assets or _ASSETS))


def _record(src: str | None = "10.10.20.5", dst: str | None = "8.8.8.8", **extra: Any) -> dict:
    rec: dict[str, Any] = {"class_uid": 4001}
    if src is not None:
        rec["src_endpoint"] = {"ip": src, "port": 51000}
    if dst is not None:
        rec["dst_endpoint"] = {"ip": dst, "port": 443}
    rec.update(extra)
    return rec


# --------------------------------------------------------------------------
# ZoneMap: longest-prefix CIDR matching


def test_zone_map_matches_longest_prefix() -> None:
    zmap = ZoneMap.from_yaml(_ASSETS)
    assert len(zmap) == 9

    assert zmap.lookup("10.10.20.5").zone == "crown-jewels"  # /24 beats /16 beats /8
    assert zmap.lookup("10.10.20.5").criticality == "critical"
    assert zmap.lookup("10.10.99.9").zone == "corp-servers"  # /16
    assert zmap.lookup("10.99.0.1").zone == "corp"  # /8
    assert zmap.lookup("8.8.8.8") is None  # no covering prefix

    assert zmap.lookup("2001:db8:aa::5").zone == "dmz-v6"  # v6 /48
    assert zmap.lookup("fd00:1234::9").zone == "corp-v6"  # v6 /32
    assert zmap.lookup("2001:4860::8888") is None


def test_zone_map_host_route_beats_covering_network(tmp_path: Path) -> None:
    assets = tmp_path / "assets.yaml"
    assets.write_text(
        "zones:\n"
        "  - {cidr: 10.0.0.0/8, zone: corp, criticality: low}\n"
        "  - {cidr: 10.1.2.0/24, zone: db-tier, criticality: high}\n"
        "  - {cidr: 10.1.2.7/32, zone: db-primary, criticality: critical}\n",
        encoding="utf-8",
    )
    zmap = ZoneMap.from_yaml(assets)
    assert zmap.lookup("10.1.2.7").zone == "db-primary"
    assert zmap.lookup("10.1.2.8").zone == "db-tier"
    assert zmap.lookup("10.5.5.5").zone == "corp"


def test_zone_map_is_empty_when_the_file_is_absent(tmp_path: Path) -> None:
    zmap = ZoneMap.from_yaml(tmp_path / "nope.yaml")
    assert len(zmap) == 0
    assert zmap.lookup("10.0.0.1") is None


def test_zone_map_skips_malformed_rows(tmp_path: Path) -> None:
    assets = tmp_path / "assets.yaml"
    assets.write_text(
        "zones:\n"
        "  - {zone: no_cidr, criticality: low}\n"
        "  - {cidr: not-a-cidr, zone: bad}\n"
        "  - {cidr: 10.0.0.0/8, zone: corp}\n",
        encoding="utf-8",
    )
    zmap = ZoneMap.from_yaml(assets)
    assert len(zmap) == 1
    assert zmap.lookup("10.1.1.1").zone == "corp"
    assert zmap.lookup("10.1.1.1").criticality is None


# --------------------------------------------------------------------------
# per-IP RFC classification


@pytest.mark.parametrize(
    ("ip", "flag"),
    [
        ("10.0.0.5", "is_private"),
        ("127.0.0.1", "is_loopback"),
        ("224.0.0.1", "is_multicast"),
        ("240.0.0.1", "is_reserved"),
    ],
)
def test_rfc_classification_flags(ip: str, flag: str) -> None:
    ctx = _enricher().enrich(_record(src=ip, dst="8.8.8.8"))["network_context"]
    assert ctx["ips"][ip][flag] is True


def test_ip_version_is_reported() -> None:
    ctx = _enricher().enrich(_record(src="10.0.0.5", dst="2001:db8:aa::1"))["network_context"]
    assert ctx["ips"]["10.0.0.5"]["ip_version"] == 4
    assert ctx["ips"]["2001:db8:aa::1"]["ip_version"] == 6


def test_public_ip_has_no_private_flags() -> None:
    ctx = _enricher().enrich(_record(src="10.0.0.5", dst="8.8.8.8"))["network_context"]
    pub = ctx["ips"]["8.8.8.8"]
    assert pub["is_private"] is False and pub["is_global"] is True
    assert pub["is_loopback"] is False and pub["is_multicast"] is False


# --------------------------------------------------------------------------
# direction inference


@pytest.mark.parametrize(
    ("src", "dst", "expected"),
    [
        ("10.0.0.5", "8.8.8.8", "outbound"),  # private -> public
        ("8.8.8.8", "10.0.0.5", "inbound"),  # public -> private
        ("10.0.0.5", "192.168.1.9", "internal"),  # private -> private
        ("8.8.8.8", "1.1.1.1", "transit"),  # public -> public
    ],
)
def test_direction_inference(src: str, dst: str, expected: str) -> None:
    ctx = _enricher().enrich(_record(src=src, dst=dst))["network_context"]
    assert ctx["direction"] == expected


def test_direction_is_absent_when_an_endpoint_is_missing() -> None:
    ctx = _enricher().enrich(_record(src="10.0.0.5", dst=None))["network_context"]
    assert "direction" not in ctx


# --------------------------------------------------------------------------
# zone attachment + IP collection


def test_zone_and_criticality_attached_for_src_and_dst() -> None:
    ctx = _enricher().enrich(_record(src="10.10.20.5", dst="192.168.1.9"))["network_context"]
    assert ctx["src_zone"] == "crown-jewels" and ctx["src_criticality"] == "critical"
    assert ctx["dst_zone"] == "dmz" and ctx["dst_criticality"] == "high"


def test_dst_zone_is_none_when_unmapped_to_any_cidr() -> None:
    ctx = _enricher().enrich(_record(src="10.10.20.5", dst="8.8.8.8"))["network_context"]
    assert ctx["dst_zone"] is None and ctx["dst_criticality"] is None


def test_every_ip_in_the_record_is_described_including_unmapped_nat() -> None:
    record = _record(
        src="10.0.0.5",
        dst="8.8.8.8",
        unmapped={"nat_src_ip": "203.0.113.10", "note": "n/a", "MAC": "00:11:22:33:44:55"},
    )
    ips = _enricher().enrich(record)["network_context"]["ips"]
    assert set(ips) == {"10.0.0.5", "8.8.8.8", "203.0.113.10"}


def test_enrich_returns_empty_when_no_ip_present() -> None:
    assert _enricher().enrich({"class_uid": 4001, "unmapped": {"note": "no ips here"}}) == {}


def test_enrich_does_not_mutate_the_record() -> None:
    record = _record()
    before = repr(record)
    _enricher().enrich(record)
    assert repr(record) == before and "enrichments" not in record


# --------------------------------------------------------------------------
# wiring


def test_is_a_valid_enricher_and_runs_air_gapped_without_asset_file(tmp_path: Path) -> None:
    enr = NetworkContextEnricher(ZoneMap.from_yaml(tmp_path / "absent.yaml"))
    assert isinstance(enr, Enricher)
    ctx = enr.enrich(_record(src="10.0.0.5", dst="8.8.8.8"))["network_context"]
    assert ctx["direction"] == "outbound"  # RFC flags + direction still work
    assert ctx["src_zone"] is None  # ...only the zone is unknown


def test_from_settings_loads_the_shipped_asset_map() -> None:
    enr = NetworkContextEnricher.from_settings(Settings(enrich=EnrichSettings()))
    ctx = enr.enrich(_record(src="10.10.20.5", dst="8.8.8.8"))["network_context"]
    assert ctx["src_zone"] == "crown-jewels"


def test_runs_end_to_end_through_the_enrichment_pipeline() -> None:
    with EnrichmentPipeline(Settings(enrich=EnrichSettings()), [_enricher()]) as pipe:
        out = pipe.enrich(_record(src="10.0.0.5", dst="8.8.8.8"))
    assert out["enrichments"]["network_context"]["direction"] == "outbound"
