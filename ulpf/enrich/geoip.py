"""GeoIP enricher — optional, offline, licence-clean.

Adds geolocation (and, if a second database is present, ASN) for the **public**
IP addresses in a record, from local MaxMind GeoLite2 ``.mmdb`` files:

* ``country_code``, ``country_name``, ``city``, ``latitude``, ``longitude``
  from ``GeoLite2-City.mmdb``;
* ``asn``, ``asn_org`` from ``GeoLite2-ASN.mmdb`` when that file is configured.

**Never a hard dependency.** If the City database (or the ``maxminddb`` reader
package) is absent, the enricher logs a clear one-line warning, sets
``enabled = False``, and every :meth:`enrich` call returns ``{}`` — the pipeline
carries on untouched. This keeps the air-gapped build free of any licence-
restricted data: the operator drops the ``.mmdb`` in out of band (see
``deploy/data/README.md``).

**Fully offline.** ``maxminddb`` memory-maps the file and answers every query
from it; there is no network access at open or lookup time.

**No auto-update.** MaxMind's ``geoipupdate`` tool/cron is a *separate* thing;
ULPF never invokes it and opens the database read-only. :data:`GeoIpEnricher.AUTO_UPDATE`
is ``False`` to make that explicit.

Private / non-global addresses are skipped entirely (no lookup, no output).
Lookups are memoized in a 100k-entry LRU cache.
"""

from __future__ import annotations

import contextlib
import functools
import logging
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

from ulpf.config.settings import Settings

_log = logging.getLogger(__name__)

_CACHE_SIZE = 100_000


class _MmdbReader(Protocol):
    """The slice of ``maxminddb.Reader`` this module uses (also lets tests fake it)."""

    def get(self, ip: str) -> Any: ...

    def close(self) -> None: ...


def _open_reader(path: str | Path | None, *, label: str) -> _MmdbReader | None:
    """Open an ``.mmdb`` read-only + memory-mapped, or return ``None`` (never raise)."""
    if path is None:
        _log.info("geoip: no %s path configured; %s lookups disabled", label, label)
        return None
    file = Path(path)
    if not file.is_file():
        _log.warning(
            "geoip: %s database not found at %s — continuing WITHOUT %s enrichment "
            "(optional; see deploy/data/README.md)",
            label,
            file,
            label,
        )
        return None
    try:
        import maxminddb  # type: ignore[import-not-found]  # optional dep: ulpf[geoip]
    except ImportError:
        _log.warning(
            "geoip: the 'maxminddb' package is not installed — %s enrichment disabled "
            "(pip install 'ulpf[geoip]')",
            label,
        )
        return None
    try:
        return maxminddb.open_database(str(file), maxminddb.MODE_MMAP)
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
        _log.error(
            "geoip: could not open %s database %s: %s — %s enrichment disabled",
            label,
            file,
            exc,
            label,
        )
        return None


class GeoIpEnricher:
    """Adds geo/ASN context for public IPs from local GeoLite2 databases."""

    name = "geoip"

    #: MaxMind auto-update (``geoipupdate``) is out of scope by design; the
    #: reader only ever reads the file it is handed.
    AUTO_UPDATE = False

    def __init__(
        self, city_reader: _MmdbReader | None = None, asn_reader: _MmdbReader | None = None
    ) -> None:
        """Take already-opened readers; ``city_reader=None`` self-disables the enricher."""
        self._city = city_reader
        self._asn = asn_reader
        self.enabled = city_reader is not None
        if not self.enabled:
            _log.warning(
                "geoip enricher DISABLED (no GeoLite2-City database) — the pipeline "
                "continues without geo enrichment"
            )
        self._lookup = functools.lru_cache(maxsize=_CACHE_SIZE)(self._lookup_uncached)

    @classmethod
    def from_settings(cls, settings: Settings) -> GeoIpEnricher:
        """Build from ``settings.enrich.geoip_db_path`` / ``geoip_asn_db_path``."""
        enrich = settings.enrich
        return cls(
            _open_reader(enrich.geoip_db_path, label="GeoLite2-City"),
            _open_reader(enrich.geoip_asn_db_path, label="GeoLite2-ASN"),
        )

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"geoip": {ip: {...}}}`` for public IPs, or ``{}`` when nothing resolves."""
        if not self.enabled:
            return {}
        resolved: dict[str, dict[str, Any]] = {}
        for ip in _public_ips(record):
            fields = dict(self._lookup(ip))
            if fields:
                resolved[ip] = fields
        return {"geoip": resolved} if resolved else {}

    def cache_info(self) -> Any:
        """Expose the LRU cache stats namedtuple (hits/misses/maxsize/currsize)."""
        return self._lookup.cache_info()

    def describe(self) -> dict[str, Any]:
        """Readiness summary for the /health endpoint."""
        if not self.enabled:
            return {"ready": False, "detail": "no GeoLite2-City database (self-disabled)"}
        asn = "with ASN" if self._asn is not None else "no ASN db"
        return {"ready": True, "detail": f"GeoLite2-City loaded ({asn})"}

    def close(self) -> None:
        """Close the underlying readers (idempotent, never raises)."""
        for reader in (self._city, self._asn):
            if reader is not None:
                with contextlib.suppress(Exception):
                    reader.close()

    # -- internals ----------------------------------------------------------

    def _lookup_uncached(self, ip: str) -> tuple[tuple[str, Any], ...]:
        """City + ASN fields for one IP, as a hashable sorted tuple (cache value)."""
        fields: dict[str, Any] = {}
        city_record = _safe_get(self._city, ip)
        if isinstance(city_record, dict):
            fields.update(_city_fields(city_record))
        asn_record = _safe_get(self._asn, ip)
        if isinstance(asn_record, dict):
            fields.update(_asn_fields(asn_record))
        return tuple(sorted(fields.items()))


def _public_ips(record: dict[str, Any]) -> list[str]:
    """Distinct globally-routable IPs in the record (endpoints + ``unmapped``)."""
    out: list[str] = []
    candidates: list[Any] = [
        _endpoint_ip(record, "src_endpoint"),
        _endpoint_ip(record, "dst_endpoint"),
    ]
    unmapped = record.get("unmapped")
    if isinstance(unmapped, dict):
        candidates.extend(unmapped.values())
    for value in candidates:
        ip = _global_ip(value)
        if ip is not None and ip not in out:
            out.append(ip)
    return out


def _endpoint_ip(record: dict[str, Any], key: str) -> Any:
    """``record[key]["ip"]`` when ``record[key]`` is a dict, else ``None``."""
    endpoint = record.get(key)
    return endpoint.get("ip") if isinstance(endpoint, dict) else None


def _global_ip(value: Any) -> str | None:
    """Canonical string of ``value`` if it is a *public* IP address, else ``None``."""
    if not isinstance(value, str):
        return None
    try:
        obj = ip_address(value)
    except ValueError:
        return None
    return str(obj) if not obj.is_private else None


def _safe_get(reader: _MmdbReader | None, ip: str) -> Any:
    """``reader.get(ip)`` guarded against a missing reader or a reader error."""
    if reader is None:
        return None
    try:
        return reader.get(ip)
    except (ValueError, KeyError):
        return None


def _city_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Pull the five city/location fields from a GeoLite2-City record; drop blanks."""
    country = record.get("country") or record.get("registered_country") or {}
    city = record.get("city") or {}
    location = record.get("location") or {}
    fields = {
        "country_code": country.get("iso_code"),
        "country_name": (country.get("names") or {}).get("en"),
        "city": (city.get("names") or {}).get("en"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
    }
    return {key: value for key, value in fields.items() if value is not None}


def _asn_fields(record: dict[str, Any]) -> dict[str, Any]:
    """Pull ``asn`` / ``asn_org`` from a GeoLite2-ASN record; drop blanks."""
    fields = {
        "asn": record.get("autonomous_system_number"),
        "asn_org": record.get("autonomous_system_organization"),
    }
    return {key: value for key, value in fields.items() if value is not None}
