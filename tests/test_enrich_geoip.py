"""Tests for :mod:`ulpf.enrich.geoip`.

The database-backed test skips cleanly when no ``GeoLite2-City.mmdb`` is present
(the file is licence-restricted and never committed). The behaviour tests use a
fake in-memory reader, so they run everywhere and need no ``maxminddb`` install.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from ulpf.config.settings import EnrichSettings, Settings
from ulpf.enrich.base import Enricher
from ulpf.enrich.geoip import GeoIpEnricher, _open_reader
from ulpf.enrich.pipeline import EnrichmentPipeline

_REAL_CITY_DB = Path(__file__).parent.parent / "deploy" / "data" / "GeoLite2-City.mmdb"

_GOOGLE_CITY = {
    "country": {"iso_code": "US", "names": {"en": "United States"}},
    "city": {"names": {"en": "Mountain View"}},
    "location": {"latitude": 37.4223, "longitude": -122.0847},
}
_GOOGLE_ASN = {"autonomous_system_number": 15169, "autonomous_system_organization": "GOOGLE"}


class _FakeReader:
    """Stands in for ``maxminddb.Reader``: ``.get(ip)`` against a dict, ``.close()``."""

    def __init__(self, table: dict[str, Any]) -> None:
        self.table = table
        self.calls: list[str] = []
        self.closed = False

    def get(self, ip: str) -> Any:
        self.calls.append(ip)
        return self.table.get(ip)

    def close(self) -> None:
        self.closed = True


def _record(src: str | None = "10.0.0.5", dst: str | None = "8.8.8.8", **extra: Any) -> dict:
    rec: dict[str, Any] = {"class_uid": 4001}
    if src is not None:
        rec["src_endpoint"] = {"ip": src, "port": 51000}
    if dst is not None:
        rec["dst_endpoint"] = {"ip": dst, "port": 443}
    rec.update(extra)
    return rec


# --------------------------------------------------------------------------
# self-disable / never a hard dependency


def test_disabled_without_a_reader_returns_empty(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="ulpf.enrich.geoip"):
        enr = GeoIpEnricher()
    assert enr.enabled is False
    assert enr.enrich(_record()) == {}
    assert any("DISABLED" in r.message for r in caplog.records)


def test_from_settings_with_missing_file_self_disables(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    missing = tmp_path / "GeoLite2-City.mmdb"
    with caplog.at_level(logging.WARNING, logger="ulpf.enrich.geoip"):
        enr = GeoIpEnricher.from_settings(Settings(enrich=EnrichSettings(geoip_db_path=missing)))
    assert enr.enabled is False
    assert enr.enrich(_record()) == {}
    assert any(str(missing) in r.message and "WITHOUT" in r.message for r in caplog.records)


def test_open_reader_returns_none_for_absent_path_and_none_path(tmp_path: Path) -> None:
    assert _open_reader(None, label="GeoLite2-City") is None
    assert _open_reader(tmp_path / "nope.mmdb", label="GeoLite2-City") is None


def test_missing_geoip_never_breaks_the_enrichment_pipeline() -> None:
    settings = Settings(enrich=EnrichSettings(geoip_db_path=Path("/no/such/City.mmdb")))
    with EnrichmentPipeline(settings, [GeoIpEnricher.from_settings(settings)]) as pipe:
        out = pipe.enrich(_record())
    assert out["class_uid"] == 4001 and out["enrichments"] == {}


def test_auto_update_is_explicitly_disabled() -> None:
    assert GeoIpEnricher.AUTO_UPDATE is False


# --------------------------------------------------------------------------
# enrichment behaviour (fake reader)


def test_public_ip_gets_city_fields_private_ip_is_skipped() -> None:
    reader = _FakeReader({"8.8.8.8": _GOOGLE_CITY})
    out = GeoIpEnricher(reader).enrich(_record(src="10.0.0.5", dst="8.8.8.8"))

    assert out == {
        "geoip": {
            "8.8.8.8": {
                "country_code": "US",
                "country_name": "United States",
                "city": "Mountain View",
                "latitude": 37.4223,
                "longitude": -122.0847,
            }
        }
    }
    assert reader.calls == ["8.8.8.8"]  # the private 10.0.0.5 was never looked up


def test_all_private_record_yields_no_lookups_and_no_output() -> None:
    reader = _FakeReader({})
    out = GeoIpEnricher(reader).enrich(_record(src="10.0.0.5", dst="192.168.1.9"))
    assert out == {}
    assert reader.calls == []


def test_asn_fields_added_when_an_asn_reader_is_present() -> None:
    city = _FakeReader({"8.8.8.8": _GOOGLE_CITY})
    asn = _FakeReader({"8.8.8.8": _GOOGLE_ASN})
    fields = GeoIpEnricher(city, asn).enrich(_record(dst="8.8.8.8"))["geoip"]["8.8.8.8"]
    assert fields["asn"] == 15169 and fields["asn_org"] == "GOOGLE"
    assert fields["country_code"] == "US"


def test_no_asn_reader_means_no_asn_fields() -> None:
    fields = GeoIpEnricher(_FakeReader({"8.8.8.8": _GOOGLE_CITY})).enrich(_record(dst="8.8.8.8"))[
        "geoip"
    ]["8.8.8.8"]
    assert "asn" not in fields and "asn_org" not in fields


def test_ip_absent_from_the_database_produces_no_entry() -> None:
    out = GeoIpEnricher(_FakeReader({})).enrich(_record(dst="8.8.8.8"))
    assert out == {}


def test_partial_record_keeps_only_the_fields_that_exist() -> None:
    reader = _FakeReader({"9.9.9.9": {"country": {"iso_code": "CH"}}})
    fields = GeoIpEnricher(reader).enrich(_record(dst="9.9.9.9"))["geoip"]["9.9.9.9"]
    assert fields == {"country_code": "CH"}


def test_public_ip_is_collected_from_unmapped_nat() -> None:
    reader = _FakeReader({"1.1.1.1": _GOOGLE_CITY})
    record = _record(src="10.0.0.5", dst="192.168.1.9", unmapped={"nat_src_ip": "1.1.1.1"})
    out = GeoIpEnricher(reader).enrich(record)
    assert set(out["geoip"]) == {"1.1.1.1"}


def test_lookups_are_lru_cached_to_100k_entries() -> None:
    reader = _FakeReader({"8.8.8.8": _GOOGLE_CITY})
    enr = GeoIpEnricher(reader)
    enr.enrich(_record(dst="8.8.8.8"))
    enr.enrich(_record(dst="8.8.8.8"))
    enr.enrich(_record(dst="8.8.8.8"))

    assert reader.calls == ["8.8.8.8"]  # only the first call hit the reader
    info = enr.cache_info()
    assert info.maxsize == 100_000
    assert info.hits >= 2


def test_is_a_valid_enricher_and_close_closes_readers() -> None:
    city, asn = _FakeReader({}), _FakeReader({})
    enr = GeoIpEnricher(city, asn)
    assert isinstance(enr, Enricher)
    enr.close()
    assert city.closed and asn.closed


def test_runs_end_to_end_through_the_enrichment_pipeline() -> None:
    enr = GeoIpEnricher(_FakeReader({"8.8.8.8": _GOOGLE_CITY}))
    with EnrichmentPipeline(Settings(enrich=EnrichSettings()), [enr]) as pipe:
        out = pipe.enrich(_record(dst="8.8.8.8"))
    assert out["enrichments"]["geoip"]["8.8.8.8"]["country_code"] == "US"


# --------------------------------------------------------------------------
# real database (skipped when the licence-restricted file is not present)


@pytest.mark.skipif(
    not _REAL_CITY_DB.is_file(),
    reason="deploy/data/GeoLite2-City.mmdb not present (optional, licence-restricted)",
)
def test_real_geolite2_city_database_resolves_a_public_ip() -> None:
    enr = GeoIpEnricher.from_settings(Settings(enrich=EnrichSettings(geoip_db_path=_REAL_CITY_DB)))
    assert enr.enabled is True
    fields = enr.enrich(_record(src="10.0.0.1", dst="8.8.8.8")).get("geoip", {}).get("8.8.8.8")
    assert fields and fields.get("country_code")
    enr.close()
