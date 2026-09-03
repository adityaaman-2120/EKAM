"""Pure-Python network-context enricher — always available, even air-gapped.

For every IP address in a normalized record this adds, under
``enrichments["network_context"]``:

* ``ip_version`` (4 or 6) and the RFC classification booleans ``is_private``
  (RFC 1918 / RFC 4193 and friends, per the stdlib), ``is_loopback``,
  ``is_multicast``, ``is_reserved``, plus ``is_global``;
* a ``zone`` and ``criticality`` from a configurable CIDR -> zone map
  (``configs/assets.yaml``), matched by **longest prefix**;
* a ``direction`` inferred from the src/dst pair:
  private -> public = ``outbound``, public -> private = ``inbound``,
  private -> private = ``internal``, public -> public = ``transit``.

There is **no external data dependency**: everything comes from the stdlib
:mod:`ipaddress` module and one small YAML file shipped with the deployment, so
the enricher behaves identically inside an air-gapped container. A missing
``assets.yaml`` simply yields ``zone = None`` (the defined fallback); the RFC
flags and direction still work.

CIDR matching uses a binary radix (prefix) trie, one per address family, giving
O(prefix-length) longest-prefix lookups independent of how many zones are
configured.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from pathlib import Path
from typing import Any

import yaml

from ulpf.config.settings import Settings
from ulpf.enrich._cidr import CidrTrie

_DIRECTION = {
    ("private", "public"): "outbound",
    ("public", "private"): "inbound",
    ("private", "private"): "internal",
    ("public", "public"): "transit",
}


@dataclass(frozen=True)
class ZoneInfo:
    """A matched asset zone: its name, criticality level, and the CIDR that hit."""

    zone: str
    criticality: str | None
    cidr: str


class ZoneMap:
    """Immutable CIDR -> :class:`ZoneInfo` index with longest-prefix lookup."""

    def __init__(
        self, entries: Iterable[tuple[IPv4Network | IPv6Network, ZoneInfo]] = ()
    ) -> None:
        """Build the longest-prefix-match index from ``(network, info)`` pairs."""
        self._trie: CidrTrie[ZoneInfo] = CidrTrie(entries)

    def __len__(self) -> int:
        """Number of configured CIDR entries."""
        return len(self._trie)

    def lookup(self, ip: str | IPv4Address | IPv6Address) -> ZoneInfo | None:
        """Return the most specific zone containing ``ip``, or ``None``."""
        return self._trie.lookup(ip)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ZoneMap:
        """Load a zone map from ``configs/assets.yaml``; empty if the file is absent."""
        file = Path(path)
        if not file.is_file():
            return cls()
        document = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        return cls(_read_zone_rows(document.get("zones") or []))


def _read_zone_rows(
    rows: list[dict[str, Any]],
) -> list[tuple[IPv4Network | IPv6Network, ZoneInfo]]:
    """Parse ``zones:`` rows into ``(network, ZoneInfo)`` pairs, skipping bad ones."""
    entries: list[tuple[IPv4Network | IPv6Network, ZoneInfo]] = []
    for row in rows:
        if not isinstance(row, dict) or "cidr" not in row:
            continue
        try:
            network = ip_network(str(row["cidr"]), strict=False)
        except ValueError:
            continue
        crit = row.get("criticality")
        entries.append(
            (
                network,
                ZoneInfo(
                    zone=str(row.get("zone", "")),
                    criticality=None if crit is None else str(crit),
                    cidr=str(network),
                ),
            )
        )
    return entries


class NetworkContextEnricher:
    """Adds RFC classification, asset zone, and direction for every IP in a record."""

    name = "network_context"

    def __init__(self, zone_map: ZoneMap | None = None) -> None:
        """Take a pre-loaded :class:`ZoneMap` (empty map = RFC flags + direction only)."""
        self._zones = zone_map if zone_map is not None else ZoneMap()

    @classmethod
    def from_settings(cls, settings: Settings) -> NetworkContextEnricher:
        """Build the enricher, loading the zone map from ``settings.enrich.assets_path``."""
        return cls(ZoneMap.from_yaml(settings.enrich.assets_path))

    def describe(self) -> dict[str, Any]:
        """Readiness summary for the /health endpoint."""
        return {"ready": True, "detail": f"{len(self._zones)} asset zones loaded"}

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"network_context": {...}}`` to merge under ``enrichments``."""
        ips = _collect_ips(record)
        if not ips:
            return {}  # nothing addressable in this record -> defined fallback

        described = {ip: self._describe(ip) for ip in ips}
        context: dict[str, Any] = {"ips": described}

        src, dst = _endpoint_ip(record, "src_endpoint"), _endpoint_ip(record, "dst_endpoint")
        direction = _infer_direction(src, dst)
        if direction is not None:
            context["direction"] = direction
        for role, addr in (("src", src), ("dst", dst)):
            if addr and addr in described:
                context[f"{role}_zone"] = described[addr]["zone"]
                context[f"{role}_criticality"] = described[addr]["criticality"]
        return {"network_context": context}

    def _describe(self, ip: str) -> dict[str, Any]:
        """Classification + zone for one address string."""
        obj = ip_address(ip)
        info = self._zones.lookup(obj)
        return {
            "ip_version": obj.version,
            "is_private": obj.is_private,
            "is_loopback": obj.is_loopback,
            "is_multicast": obj.is_multicast,
            "is_reserved": obj.is_reserved,
            "is_global": obj.is_global,
            "zone": info.zone if info else None,
            "criticality": info.criticality if info else None,
        }


def _scope(ip: str) -> str:
    """``"private"`` for a non-globally-routable address, else ``"public"``."""
    return "private" if ip_address(ip).is_private else "public"


def _infer_direction(src: str | None, dst: str | None) -> str | None:
    """Map the (src scope, dst scope) pair to outbound/inbound/internal/transit."""
    if not src or not dst:
        return None
    return _DIRECTION.get((_scope(src), _scope(dst)))


def _endpoint_ip(record: dict[str, Any], key: str) -> str | None:
    """The validated ``ip`` string of ``record[key]``, or ``None``."""
    endpoint = record.get(key)
    if not isinstance(endpoint, dict):
        return None
    return _valid_ip(endpoint.get("ip"))


def _collect_ips(obj: Any, found: list[str] | None = None) -> list[str]:
    """Every distinct IP string in the record: any ``ip`` key, plus IPs in ``unmapped``."""
    found = [] if found is None else found
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "ip":
                _append_ip(value, found)
            elif key == "unmapped" and isinstance(value, dict):
                for item in value.values():
                    _append_ip(item, found)
            else:
                _collect_ips(value, found)
    elif isinstance(obj, list):
        for item in obj:
            _collect_ips(item, found)
    return found


def _append_ip(value: Any, found: list[str]) -> None:
    """Append ``value`` to ``found`` if it is an IP string not already present."""
    ip = _valid_ip(value)
    if ip is not None and ip not in found:
        found.append(ip)


def _valid_ip(value: Any) -> str | None:
    """Return the canonical string form of ``value`` if it is an IP address."""
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None
