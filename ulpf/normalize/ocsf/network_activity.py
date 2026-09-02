"""OCSF **Network Activity** (class_uid 4001, category_uid 4), schema 1.5.0.

The perimeter devices ULPF ingests — firewalls, IDS/IPS, proxies, VPN, WAF,
routers, flow logs — map overwhelmingly onto this one class. This module pins
its shape: the required/recommended attributes, the sub-object key sets
(``connection_info``, ``traffic``, ``firewall_rule``), the enums, small builders,
and :func:`validate_4001`.

KNOWN GAPS (limitations of the OCSF standard itself, not of this code):

* **NAT address pairs.** OCSF 1.5.0 Network Activity has no symmetric field for
  the pre-/post-translation address+port pair a NAT device reports (original vs
  translated source, original vs translated destination). There is one
  ``src_endpoint`` and one ``dst_endpoint`` and no ``*_nat_endpoint``. ULPF puts
  the translated addresses under ``unmapped`` (e.g. ``unmapped["nat.src_ip"]``).
* **Firewall zones.** PAN-OS, FortiGate and ASA all report a source zone and a
  destination zone; OCSF has no first-class ``zone`` attribute on an endpoint or
  on the event. ULPF puts them under ``unmapped`` (e.g. ``unmapped["src_zone"]``).

Both are properties of the standard as of 1.5.0. If a later OCSF version adds
these fields, the mappings should move out of ``unmapped``.
"""

from __future__ import annotations

from typing import Any

from ulpf.normalize.ocsf.base import check_class, check_enum, check_required, strip_none

CLASS_UID = 4001
CATEGORY_UID = 4

ACTIVITY_IDS: dict[int, str] = {
    0: "Unknown",
    1: "Open",
    2: "Close",
    3: "Reset",
    4: "Fail",
    5: "Refuse",
    6: "Traffic",
    99: "Other",
}
ACTION_IDS: dict[int, str] = {0: "Unknown", 1: "Allowed", 2: "Denied", 99: "Other"}
DIRECTION_IDS: dict[int, str] = {0: "Unknown", 1: "Inbound", 2: "Outbound", 3: "Lateral", 99: "Other"}
BOUNDARY_IDS: dict[int, str] = {
    0: "Unknown",
    1: "Localhost",
    2: "Internal",
    3: "External",
    4: "Same VPC",
    99: "Other",
}
STATUS_IDS: dict[int, str] = {0: "Unknown", 1: "Success", 2: "Failure", 99: "Other"}

# Sub-object shapes.
CONNECTION_INFO_KEYS: tuple[str, ...] = (
    "uid",
    "direction",
    "direction_id",
    "protocol_name",
    "protocol_num",
    "tcp_flags",
    "boundary",
    "boundary_id",
)
TRAFFIC_KEYS: tuple[str, ...] = (
    "bytes",
    "bytes_in",
    "bytes_out",
    "packets",
    "packets_in",
    "packets_out",
)
FIREWALL_RULE_KEYS: tuple[str, ...] = ("uid", "name")

# ULPF requires `src_endpoint` (OCSF lists it as *recommended*): a perimeter
# network event with no source is not actionable. Everything else OCSF-required
# is the base-event set.
_REQUIRED_SCALAR: tuple[str, ...] = (
    "class_uid",
    "category_uid",
    "activity_id",
    "type_uid",
    "severity_id",
    "time",
)
_REQUIRED_OBJECT: tuple[str, ...] = ("metadata", "src_endpoint")
REQUIRED_4001: tuple[str, ...] = _REQUIRED_SCALAR + _REQUIRED_OBJECT
RECOMMENDED_4001: tuple[str, ...] = (
    "dst_endpoint",
    "connection_info",
    "traffic",
    "firewall_rule",
    "action",
    "action_id",
    "disposition",
    "status_id",
    "severity",
    "activity_name",
    "type_name",
    "unmapped",
)

CLASS_SHAPE: dict[str, Any] = {
    "class_uid": CLASS_UID,
    "category_uid": CATEGORY_UID,
    "required": REQUIRED_4001,
    "recommended": RECOMMENDED_4001,
    "objects": {
        "connection_info": CONNECTION_INFO_KEYS,
        "traffic": TRAFFIC_KEYS,
        "firewall_rule": FIREWALL_RULE_KEYS,
    },
    "enums": {
        "activity_id": ACTIVITY_IDS,
        "action_id": ACTION_IDS,
        "direction_id": DIRECTION_IDS,
        "boundary_id": BOUNDARY_IDS,
        "status_id": STATUS_IDS,
    },
}


def build_connection_info(
    *,
    uid: str | None = None,
    direction: str | None = None,
    direction_id: int | None = None,
    protocol_name: str | None = None,
    protocol_num: int | None = None,
    tcp_flags: int | None = None,
    boundary: str | None = None,
    boundary_id: int | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``connection_info`` object, omitting unset fields."""
    return strip_none(
        {
            "uid": uid,
            "direction": direction,
            "direction_id": direction_id,
            "protocol_name": protocol_name,
            "protocol_num": protocol_num,
            "tcp_flags": tcp_flags,
            "boundary": boundary,
            "boundary_id": boundary_id,
        }
    )


def build_traffic(
    *,
    bytes_: int | None = None,
    bytes_in: int | None = None,
    bytes_out: int | None = None,
    packets: int | None = None,
    packets_in: int | None = None,
    packets_out: int | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``traffic`` object, omitting unset fields."""
    return strip_none(
        {
            "bytes": bytes_,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "packets": packets,
            "packets_in": packets_in,
            "packets_out": packets_out,
        }
    )


def build_firewall_rule(*, uid: str | None = None, name: str | None = None) -> dict[str, Any]:
    """Build an OCSF ``firewall_rule`` object, omitting unset fields."""
    return strip_none({"uid": uid, "name": name})


def new_record(
    *,
    activity_id: int,
    severity_id: int,
    time: int,
    metadata: dict[str, Any],
    src_endpoint: dict[str, Any],
    dst_endpoint: dict[str, Any] | None = None,
    connection_info: dict[str, Any] | None = None,
    traffic: dict[str, Any] | None = None,
    firewall_rule: dict[str, Any] | None = None,
    action_id: int | None = None,
    disposition: str | None = None,
    status_id: int | None = None,
    unmapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a Network Activity record. Run :func:`ulpf.normalize.ocsf.base.finalize` after."""
    return strip_none(
        {
            "class_uid": CLASS_UID,
            "category_uid": CATEGORY_UID,
            "activity_id": activity_id,
            "activity_name": ACTIVITY_IDS.get(activity_id),
            "severity_id": severity_id,
            "time": time,
            "metadata": metadata,
            "src_endpoint": src_endpoint,
            "dst_endpoint": dst_endpoint,
            "connection_info": connection_info,
            "traffic": traffic,
            "firewall_rule": firewall_rule,
            "action_id": action_id,
            "action": ACTION_IDS.get(action_id) if action_id is not None else None,
            "disposition": disposition,
            "status_id": status_id,
            "unmapped": unmapped,
        }
    )


def validate_4001(record: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the record satisfies the 4001 profile."""
    problems = check_required(record, scalars=_REQUIRED_SCALAR, objects=_REQUIRED_OBJECT)
    problems += check_class(record, CLASS_UID, CATEGORY_UID)
    problems += check_enum(record, "activity_id", ACTIVITY_IDS, label="Network Activity value")
    problems += check_enum(record, "action_id", ACTION_IDS, label="valid action")
    return problems


validate = validate_4001
