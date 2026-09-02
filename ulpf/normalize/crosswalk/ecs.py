"""OCSF -> Elastic Common Schema (ECS) crosswalk.

:func:`to_ecs` projects a finalized OCSF record (see
:mod:`ulpf.normalize.ocsf`) onto an ECS document suitable for an Elastic /
OpenSearch data stream. It is a **lossy, best-effort** mapping: the canonical,
lossless record is the OCSF one; this is a convenience view for tools that speak
ECS.

Field mappings (OCSF -> ECS):

* ``src_endpoint.ip``            -> ``source.ip``
* ``src_endpoint.port``          -> ``source.port``
* ``dst_endpoint.ip/port/mac``   -> ``destination.ip/port/mac``
* ``connection_info.protocol_name`` -> ``network.transport``
* ``connection_info.protocol_num``  -> ``network.iana_number``
* ``traffic.bytes_out``          -> ``source.bytes``
* ``traffic.bytes_in``           -> ``destination.bytes``
* ``action``                     -> ``event.action``
* ``severity_id``                -> ``event.severity``
* ``time`` (epoch ns)            -> ``@timestamp`` (ISO 8601, UTC, ``Z``)
* ``class_uid``                  -> ``event.category`` / ``event.type`` /
  ``event.kind`` via :data:`_CLASS_MAP`
* ``firewall_rule.name/uid``     -> ``rule.name`` / ``rule.id``
  (falling back to ``finding_info.title`` / ``finding_info.uid`` for findings)
* ``metadata.product.vendor_name`` -> ``observer.vendor``
* ``metadata.product.name``      -> ``observer.product``
* ``metadata.uid``               -> ``event.id``

**ECS carries fields OCSF 1.5.0 does not** — a useful point in its own right.
These are recovered from ``unmapped`` (where the OCSF mapper had to park them):

* ``unmapped.nat_src_ip`` / ``nat_src_port`` -> ``source.nat.ip`` / ``source.nat.port``
* ``unmapped.nat_dst_ip`` / ``nat_dst_port`` -> ``destination.nat.ip`` / ``destination.nat.port``
* ``unmapped.src_zone``  -> ``observer.ingress.zone``
* ``unmapped.dst_zone``  -> ``observer.egress.zone``

Finally ``related.ip`` is populated with every distinct IP in the event
(endpoints + NAT addresses), the ECS idiom for "pivot on any address".
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

ECS_VERSION = "8.11.0"

# class_uid -> (event.category, event.type, event.kind). ECS `category` and
# `type` are always arrays (a document may sit in several categories).
_CLASS_MAP: dict[int, tuple[list[str], list[str], str]] = {
    4001: (["network"], ["connection"], "event"),
    4002: (["network", "web"], ["connection", "protocol"], "event"),
    4003: (["network"], ["connection", "protocol"], "event"),
    2004: (["intrusion_detection"], ["info"], "alert"),
}


def to_ecs(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one finalized OCSF record into an ECS document.

    The OCSF record is not modified. Empty branches (no value on either side of
    a mapping) are dropped, so the result contains only populated fields.
    """
    unmapped = _as_dict(ocsf.get("unmapped"))
    doc: dict[str, Any] = {
        "@timestamp": _iso8601(ocsf.get("time")),
        "ecs": {"version": ECS_VERSION},
        "event": _event(ocsf),
        "source": _endpoint(ocsf.get("src_endpoint"), _traffic_bytes(ocsf, "out"), unmapped, "src"),
        "destination": _endpoint(
            ocsf.get("dst_endpoint"), _traffic_bytes(ocsf, "in"), unmapped, "dst"
        ),
        "network": _network(ocsf),
        "rule": _rule(ocsf),
        "observer": _observer(ocsf, unmapped),
    }
    related = _related_ips(ocsf, unmapped)
    if related:
        doc["related"] = {"ip": related}
    return _prune(doc)


def _event(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Build the ``event.*`` sub-tree, including the class_uid -> category table."""
    categories, types, kind = _CLASS_MAP.get(ocsf.get("class_uid"), ([], [], "event"))
    metadata = _as_dict(ocsf.get("metadata"))
    return {
        "kind": kind,
        "category": list(categories),
        "type": list(types),
        "action": ocsf.get("action"),
        "severity": ocsf.get("severity_id"),
        "id": metadata.get("uid"),
    }


def _endpoint(
    endpoint: Any, byte_count: int | None, unmapped: Mapping[str, Any], side: str
) -> dict[str, Any]:
    """Build ``source.*`` / ``destination.*`` from an OCSF endpoint + NAT fields."""
    ep = _as_dict(endpoint)
    return {
        "ip": ep.get("ip"),
        "port": ep.get("port"),
        "mac": ep.get("mac"),
        "domain": ep.get("hostname"),
        "bytes": byte_count,
        "nat": {
            "ip": unmapped.get(f"nat_{side}_ip"),
            "port": _to_int(unmapped.get(f"nat_{side}_port")),
        },
    }


def _network(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Build ``network.*`` from ``connection_info`` and ``traffic``."""
    conn = _as_dict(ocsf.get("connection_info"))
    out_bytes, in_bytes = _traffic_bytes(ocsf, "out"), _traffic_bytes(ocsf, "in")
    total = None
    if out_bytes is not None or in_bytes is not None:
        total = (out_bytes or 0) + (in_bytes or 0)
    transport = conn.get("protocol_name")
    return {
        "transport": transport.lower() if isinstance(transport, str) else transport,
        "iana_number": _to_int(conn.get("protocol_num")),
        "bytes": total if total is not None else _as_dict(ocsf.get("traffic")).get("bytes"),
    }


def _rule(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """``rule.*`` from ``firewall_rule``, falling back to ``finding_info``."""
    fw_rule = _as_dict(ocsf.get("firewall_rule"))
    finding = _as_dict(ocsf.get("finding_info"))
    return {
        "name": fw_rule.get("name") or finding.get("title"),
        "id": fw_rule.get("uid") or finding.get("uid"),
        "category": finding.get("types"),
    }


def _observer(ocsf: Mapping[str, Any], unmapped: Mapping[str, Any]) -> dict[str, Any]:
    """``observer.*`` — vendor/product plus the firewall zones ECS models natively."""
    product = _as_dict(_as_dict(ocsf.get("metadata")).get("product"))
    return {
        "vendor": product.get("vendor_name"),
        "product": product.get("name"),
        "ingress": {"zone": unmapped.get("src_zone")},
        "egress": {"zone": unmapped.get("dst_zone")},
    }


def _related_ips(ocsf: Mapping[str, Any], unmapped: Mapping[str, Any]) -> list[str]:
    """Every distinct IP in the event (endpoints + NAT), sorted for determinism."""
    found: set[str] = set()
    _collect_ips(ocsf, found)
    for key in ("nat_src_ip", "nat_dst_ip"):
        value = unmapped.get(key)
        if isinstance(value, str) and value:
            found.add(value)
    return sorted(found)


def _collect_ips(obj: Any, out: set[str]) -> None:
    """Recursively gather every scalar stored under an ``ip`` key."""
    if isinstance(obj, Mapping):
        for key, value in obj.items():
            if key == "ip" and isinstance(value, str) and value:
                out.add(value)
            else:
                _collect_ips(value, out)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _collect_ips(item, out)


def _traffic_bytes(ocsf: Mapping[str, Any], direction: str) -> int | None:
    """``traffic.bytes_out`` (-> source) or ``traffic.bytes_in`` (-> destination)."""
    return _to_int(_as_dict(ocsf.get("traffic")).get(f"bytes_{direction}"))


def _iso8601(epoch_ns: Any) -> str | None:
    """UTC epoch nanoseconds -> ISO 8601 string with a ``Z`` suffix."""
    if not isinstance(epoch_ns, int) or isinstance(epoch_ns, bool):
        return None
    moment = datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=epoch_ns // 1000)
    return moment.isoformat().replace("+00:00", "Z")


def _as_dict(value: Any) -> dict[str, Any]:
    """Return ``value`` if it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _to_int(value: Any) -> int | None:
    """Coerce digit strings / ints to ``int``; ``None`` for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None


def _prune(value: Any) -> Any:
    """Recursively drop ``None`` / empty-dict / empty-list / empty-string entries."""
    if isinstance(value, dict):
        cleaned = {key: _prune(item) for key, item in value.items()}
        return {key: item for key, item in cleaned.items() if item not in (None, {}, [], "")}
    if isinstance(value, list):
        return [_prune(item) for item in value if _prune(item) not in (None, {}, [], "")]
    return value
