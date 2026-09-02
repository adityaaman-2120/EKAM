"""OCSF -> Splunk Common Information Model (CIM) crosswalk.

:func:`to_cim` projects a finalized OCSF record (see
:mod:`ulpf.normalize.ocsf`) onto the flat, tagged field set Splunk's CIM data
models expect. Like the ECS crosswalk it is **lossy and read-only**: the OCSF
record is the canonical form; this is a convenience view for Splunk searches and
accelerated data models.

A CIM event is a flat ``{field: value}`` dict plus a multivalue ``tags`` field
that binds it to a data model:

* class 4001 Network Activity -> **Network Traffic** model
  (``src``/``src_port``/``dest``/``dest_port``/``transport``/``action``/
  ``bytes``/``bytes_in``/``bytes_out``/``packets``/``rule``/``vendor_product``),
  ``tags = ["network", "communicate"]``.
* class 2004 Detection Finding -> **Intrusion Detection** model
  (``signature``/``signature_id``/``severity``/``src``/``dest``/``ids_type``/
  ``vendor_product``), ``tags = ["ids", "attack"]``.

Any other class yields the common ``src``/``dest`` fields with no tags.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# OCSF action_id / action -> CIM Network Traffic `action` vocabulary.
_TRAFFIC_ACTION: dict[Any, str] = {
    1: "allowed",
    2: "blocked",
    "Allowed": "allowed",
    "Denied": "blocked",
    "Blocked": "blocked",
    "Dropped": "blocked",
}

# OCSF severity_id -> CIM severity string.
_SEVERITY: dict[int, str] = {
    0: "unknown",
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "critical",
}


def to_cim(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Convert one finalized OCSF record into CIM fields + ``tags``.

    The OCSF record is not modified. Fields with no value are omitted; ``tags``
    is always present (empty for an unrecognized class).
    """
    class_uid = ocsf.get("class_uid")
    if class_uid == 4001:
        fields, tags = _network_traffic(ocsf), ["network", "communicate"]
    elif class_uid == 2004:
        fields, tags = _intrusion_detection(ocsf), ["ids", "attack"]
    else:
        fields, tags = _common(ocsf), []
    result = {key: value for key, value in fields.items() if value is not None}
    result["tags"] = tags
    return result


def _network_traffic(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Build the CIM Network Traffic field set from an OCSF 4001 record."""
    src, dst = _as_dict(ocsf.get("src_endpoint")), _as_dict(ocsf.get("dst_endpoint"))
    conn, traffic = _as_dict(ocsf.get("connection_info")), _as_dict(ocsf.get("traffic"))
    bytes_out, bytes_in = _to_int(traffic.get("bytes_out")), _to_int(traffic.get("bytes_in"))
    return {
        "src": src.get("ip"),
        "src_port": _to_int(src.get("port")),
        "dest": dst.get("ip"),
        "dest_port": _to_int(dst.get("port")),
        "transport": _lower(conn.get("protocol_name")),
        "action": _traffic_action(ocsf),
        "bytes": _sum(bytes_out, bytes_in, fallback=_to_int(traffic.get("bytes"))),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets": _sum(
            _to_int(traffic.get("packets_out")),
            _to_int(traffic.get("packets_in")),
            fallback=_to_int(traffic.get("packets")),
        ),
        "rule": _as_dict(ocsf.get("firewall_rule")).get("name")
        or _as_dict(ocsf.get("firewall_rule")).get("uid"),
        "vendor_product": _vendor_product(ocsf),
    }


def _intrusion_detection(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Build the CIM Intrusion Detection field set from an OCSF 2004 record."""
    finding = _as_dict(ocsf.get("finding_info"))
    return {
        "signature": finding.get("title"),
        "signature_id": finding.get("uid"),
        "severity": _severity(ocsf),
        "src": _as_dict(ocsf.get("src_endpoint")).get("ip"),
        "dest": _as_dict(ocsf.get("dst_endpoint")).get("ip"),
        "ids_type": "network",  # ULPF only ingests perimeter (network) sensors
        "vendor_product": _vendor_product(ocsf),
    }


def _common(ocsf: Mapping[str, Any]) -> dict[str, Any]:
    """Fallback field set for a class with no CIM data-model mapping."""
    return {
        "src": _as_dict(ocsf.get("src_endpoint")).get("ip"),
        "dest": _as_dict(ocsf.get("dst_endpoint")).get("ip"),
        "vendor_product": _vendor_product(ocsf),
    }


def _traffic_action(ocsf: Mapping[str, Any]) -> str | None:
    """OCSF ``action_id`` / ``action`` / ``disposition`` -> CIM traffic action."""
    for candidate in (ocsf.get("action_id"), ocsf.get("action"), ocsf.get("disposition")):
        if candidate in _TRAFFIC_ACTION:
            return _TRAFFIC_ACTION[candidate]
    return None


def _severity(ocsf: Mapping[str, Any]) -> str | None:
    """CIM severity string from the OCSF ``severity`` name or ``severity_id``."""
    name = ocsf.get("severity")
    if isinstance(name, str) and name:
        return name.lower()
    return _SEVERITY.get(ocsf.get("severity_id"))


def _vendor_product(ocsf: Mapping[str, Any]) -> str | None:
    """``"<vendor> <product>"`` from ``metadata.product``; whichever half exists."""
    product = _as_dict(_as_dict(ocsf.get("metadata")).get("product"))
    parts = [product.get("vendor_name"), product.get("name")]
    joined = " ".join(part for part in parts if part)
    return joined or None


def _sum(first: int | None, second: int | None, *, fallback: int | None) -> int | None:
    """``first + second`` when either is set, else ``fallback``."""
    if first is None and second is None:
        return fallback
    return (first or 0) + (second or 0)


def _lower(value: Any) -> Any:
    """Lowercase a string, pass anything else through untouched."""
    return value.lower() if isinstance(value, str) else value


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
