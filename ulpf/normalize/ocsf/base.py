"""OCSF constants and record builders (OCSF schema **1.5.0**).

:data:`OCSF_VERSION` is the single pin for the schema version; it is written into
every record's ``metadata.version`` by :func:`build_metadata`. The rest of this
module is small, dependency-free helpers a source-definition mapper composes:

* :data:`CATEGORIES` / :data:`SEVERITY_ID` / :data:`CLASS_NAMES` /
  :data:`ACTIVITY_NAMES` — the lookup tables.
* :func:`build_metadata`, :func:`build_endpoint` — object builders that omit
  unset fields.
* :func:`type_uid` — the ``class_uid * 100 + activity_id`` derivation.
* :func:`finalize` — fills the derived name fields (``type_uid``, ``type_name``,
  ``class_name``, ``category_name``, ``severity``) and strips ``None`` values
  recursively, returning a clean copy.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

OCSF_VERSION = "1.5.0"

CATEGORIES: dict[int, str] = {
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
    7: "Remediation",
    8: "Unmanned Systems",
}

SEVERITY_ID: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
    99: "Other",
}

# Perimeter-relevant OCSF classes.
CLASS_NAMES: dict[int, str] = {
    1001: "File System Activity",
    2004: "Detection Finding",
    3002: "Authentication",
    4001: "Network Activity",
    4002: "HTTP Activity",
    4003: "DNS Activity",
    4004: "DHCP Activity",
    4005: "RDP Activity",
    4006: "SMB Activity",
    4007: "SSH Activity",
    4008: "FTP Activity",
    4009: "Email Activity",
    4013: "NTP Activity",
    6003: "API Activity",
}

# activity_id -> name, per class (only classes with a non-generic enum listed).
ACTIVITY_NAMES: dict[int, dict[int, str]] = {
    4001: {
        0: "Unknown",
        1: "Open",
        2: "Close",
        3: "Reset",
        4: "Fail",
        5: "Refuse",
        6: "Traffic",
        99: "Other",
    },
    4002: {
        0: "Unknown",
        1: "Connect",
        2: "Delete",
        3: "Get",
        4: "Head",
        5: "Options",
        6: "Post",
        7: "Put",
        8: "Trace",
        99: "Other",
    },
    4003: {0: "Unknown", 1: "Query", 2: "Response", 6: "Traffic", 99: "Other"},
    3002: {0: "Unknown", 1: "Logon", 2: "Logoff", 3: "Authentication Ticket", 99: "Other"},
    2004: {0: "Unknown", 1: "Create", 2: "Update", 3: "Close", 99: "Other"},
}


def type_uid(class_uid: int, activity_id: int) -> int:
    """Return the OCSF ``type_uid`` (``class_uid * 100 + activity_id``)."""
    return class_uid * 100 + activity_id


def strip_none(value: Any) -> Any:
    """Recursively drop ``None`` entries from dicts and ``None`` items from lists."""
    if isinstance(value, dict):
        return {key: strip_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [strip_none(item) for item in value if item is not None]
    return value


def build_metadata(
    event_uid: str,
    product_vendor: str | None,
    product_name: str | None,
    mapping_version: str,
    logged_time: int | None,
) -> dict[str, Any]:
    """Build an OCSF ``metadata`` object.

    ``version`` is pinned to :data:`OCSF_VERSION`; ``log_version`` carries the
    ULPF source-definition version. Unset fields are omitted.
    """
    return strip_none(
        {
            "uid": event_uid,
            "version": OCSF_VERSION,
            "log_version": mapping_version,
            "logged_time": logged_time,
            "product": {"vendor_name": product_vendor, "name": product_name},
        }
    )


def build_endpoint(
    ip: str | None,
    port: int | None,
    hostname: str | None = None,
    interface: str | None = None,
    mac: str | None = None,
) -> dict[str, Any]:
    """Build an OCSF endpoint object, omitting any field that is ``None``."""
    return strip_none(
        {
            "ip": ip,
            "port": port,
            "hostname": hostname,
            "interface_name": interface,
            "mac": mac,
        }
    )


def finalize(record: dict[str, Any]) -> dict[str, Any]:
    """Fill derived name fields and strip ``None`` values; returns a new dict.

    Sets ``type_uid``/``type_name``/``activity_name`` (when ``class_uid`` and
    ``activity_id`` are present), ``class_name``, ``category_name`` and
    ``severity`` from the lookup tables, then applies :func:`strip_none` to the
    whole record. ``activity_name`` is the OCSF caption for ``activity_id`` and
    is only filled when a source did not already map it.
    """
    out = deepcopy(record)

    class_uid = out.get("class_uid")
    if class_uid is not None:
        class_name = CLASS_NAMES.get(class_uid)
        if class_name is not None:
            out["class_name"] = class_name
        activity_id = out.get("activity_id")
        if activity_id is not None:
            out["type_uid"] = type_uid(class_uid, activity_id)
            activity_name = ACTIVITY_NAMES.get(class_uid, {}).get(activity_id)
            if activity_name and not out.get("activity_name"):
                out["activity_name"] = activity_name
            if class_name is not None:
                out["type_name"] = f"{class_name}: {activity_name}" if activity_name else class_name

    category_uid = out.get("category_uid")
    if category_uid in CATEGORIES:
        out["category_name"] = CATEGORIES[category_uid]

    severity_id = out.get("severity_id")
    if severity_id in SEVERITY_ID:
        out["severity"] = SEVERITY_ID[severity_id]

    return strip_none(out)


# -- shared validation helpers (used by every per-class ``validate_*``) ------


def check_required(
    record: dict[str, Any], *, scalars: tuple[str, ...], objects: tuple[str, ...]
) -> list[str]:
    """List missing required attributes.

    ``scalars`` may legitimately be ``0``/``False`` — only ``None``/absent is a
    failure. ``objects`` must be non-empty dicts. When ``metadata`` is required,
    ``metadata.uid`` is checked too (requirement *d*).
    """
    problems: list[str] = []
    for attr in scalars:
        if record.get(attr) is None:
            problems.append(f"missing required attribute: {attr}")
    for attr in objects:
        value = record.get(attr)
        if not isinstance(value, dict) or not value:
            problems.append(f"missing required attribute: {attr}")
    metadata = record.get("metadata")
    if (
        "metadata" in objects
        and isinstance(metadata, dict)
        and metadata
        and not metadata.get("uid")
    ):
        problems.append("metadata.uid is required")
    return problems


def check_class(record: dict[str, Any], class_uid: int, category_uid: int) -> list[str]:
    """List class_uid/category_uid mismatches (a present-but-wrong value is an error)."""
    problems: list[str] = []
    if record.get("class_uid") not in (None, class_uid):
        problems.append(f"class_uid must be {class_uid}, got {record['class_uid']!r}")
    if record.get("category_uid") not in (None, category_uid):
        problems.append(f"category_uid must be {category_uid}, got {record['category_uid']!r}")
    return problems


def check_enum(
    record: dict[str, Any], field: str, allowed: dict[int, str], *, label: str
) -> list[str]:
    """One-item list if ``record[field]`` is present but not an ``allowed`` key."""
    value = record.get(field)
    if field in record and value is not None and value not in allowed:
        return [f"{field} {value!r} is not a {label}"]
    return []
