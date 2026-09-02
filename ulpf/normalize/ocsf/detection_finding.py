"""OCSF **Detection Finding** (class_uid 2004, category_uid 2), schema 1.5.0.

Where Suricata, Snort, and IDS/IPS alerts land. Same layout as
:mod:`ulpf.normalize.ocsf.network_activity`: enums, required/recommended sets,
builders, and :func:`validate_2004`.

KNOWN GAPS (limitations of the standard, not of this code):

* **Rule metadata.** OCSF ``finding_info`` carries a title, description, and
  ``types``; the free-form ``metadata`` an IDS attaches to a rule (created_at,
  updated_at, mitre attack refs as raw strings, performance impact, ...) has no
  home and goes to ``unmapped``.
* **Packet-level evidence.** ``evidences`` is polymorphic but has no first-class
  slot for the raw triggering packet / PCAP offset; that reference goes to
  ``unmapped``.
"""

from __future__ import annotations

from typing import Any

from ulpf.normalize.ocsf.base import check_class, check_enum, check_required, strip_none

CLASS_UID = 2004
CATEGORY_UID = 2

ACTIVITY_IDS: dict[int, str] = {0: "Unknown", 1: "Create", 2: "Update", 3: "Close", 99: "Other"}
CONFIDENCE_IDS: dict[int, str] = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 99: "Other"}
RISK_LEVEL_IDS: dict[int, str] = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
STATUS_IDS: dict[int, str] = {
    0: "Unknown",
    1: "New",
    2: "In Progress",
    3: "Suppressed",
    4: "Resolved",
    99: "Other",
}
ANALYTIC_TYPE_IDS: dict[int, str] = {
    0: "Unknown",
    1: "Rule",
    2: "Behavioral",
    3: "Statistical",
    4: "Learning (ML/DL)",
    5: "Fingerprinting",
    6: "Tagging",
    99: "Other",
}

FINDING_INFO_KEYS: tuple[str, ...] = ("uid", "title", "desc", "types", "analytic")
ANALYTIC_KEYS: tuple[str, ...] = ("name", "type", "type_id", "uid")

_REQUIRED_SCALAR: tuple[str, ...] = (
    "class_uid",
    "category_uid",
    "activity_id",
    "type_uid",
    "severity_id",
    "time",
)
_REQUIRED_OBJECT: tuple[str, ...] = ("metadata", "finding_info")
REQUIRED_2004: tuple[str, ...] = _REQUIRED_SCALAR + _REQUIRED_OBJECT
RECOMMENDED_2004: tuple[str, ...] = (
    "src_endpoint",
    "dst_endpoint",
    "confidence_id",
    "confidence",
    "risk_level_id",
    "risk_level",
    "evidences",
    "status_id",
    "severity",
    "activity_name",
    "type_name",
    "unmapped",
)

CLASS_SHAPE: dict[str, Any] = {
    "class_uid": CLASS_UID,
    "category_uid": CATEGORY_UID,
    "required": REQUIRED_2004,
    "recommended": RECOMMENDED_2004,
    "objects": {"finding_info": FINDING_INFO_KEYS, "analytic": ANALYTIC_KEYS},
    "enums": {
        "activity_id": ACTIVITY_IDS,
        "confidence_id": CONFIDENCE_IDS,
        "risk_level_id": RISK_LEVEL_IDS,
        "status_id": STATUS_IDS,
        "analytic.type_id": ANALYTIC_TYPE_IDS,
    },
}


def build_analytic(
    *,
    name: str | None = None,
    type_: str | None = None,
    type_id: int | None = None,
    uid: str | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``analytic`` object, omitting unset fields."""
    return strip_none({"name": name, "type": type_, "type_id": type_id, "uid": uid})


def build_finding_info(
    *,
    uid: str,
    title: str | None = None,
    desc: str | None = None,
    types: list[str] | None = None,
    analytic: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``finding_info`` object (``uid`` is required)."""
    return strip_none(
        {"uid": uid, "title": title, "desc": desc, "types": types, "analytic": analytic}
    )


def new_record(
    *,
    activity_id: int,
    severity_id: int,
    time: int,
    metadata: dict[str, Any],
    finding_info: dict[str, Any],
    confidence_id: int | None = None,
    risk_level_id: int | None = None,
    evidences: list[dict[str, Any]] | None = None,
    src_endpoint: dict[str, Any] | None = None,
    dst_endpoint: dict[str, Any] | None = None,
    status_id: int | None = None,
    unmapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a Detection Finding record. Run ``ocsf.base.finalize`` after."""
    return strip_none(
        {
            "class_uid": CLASS_UID,
            "category_uid": CATEGORY_UID,
            "activity_id": activity_id,
            "activity_name": ACTIVITY_IDS.get(activity_id),
            "severity_id": severity_id,
            "time": time,
            "metadata": metadata,
            "finding_info": finding_info,
            "confidence_id": confidence_id,
            "confidence": CONFIDENCE_IDS.get(confidence_id) if confidence_id is not None else None,
            "risk_level_id": risk_level_id,
            "risk_level": RISK_LEVEL_IDS.get(risk_level_id) if risk_level_id is not None else None,
            "evidences": evidences,
            "src_endpoint": src_endpoint,
            "dst_endpoint": dst_endpoint,
            "status_id": status_id,
            "unmapped": unmapped,
        }
    )


def validate_2004(record: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the record satisfies the 2004 profile."""
    problems = check_required(record, scalars=_REQUIRED_SCALAR, objects=_REQUIRED_OBJECT)
    problems += check_class(record, CLASS_UID, CATEGORY_UID)
    problems += check_enum(record, "activity_id", ACTIVITY_IDS, label="Detection Finding value")
    problems += check_enum(record, "confidence_id", CONFIDENCE_IDS, label="valid confidence_id")
    problems += check_enum(record, "risk_level_id", RISK_LEVEL_IDS, label="valid risk_level_id")
    problems += check_enum(record, "status_id", STATUS_IDS, label="valid status_id")
    finding_info = record.get("finding_info")
    if isinstance(finding_info, dict) and finding_info and not finding_info.get("uid"):
        problems.append("finding_info.uid is required")
    return problems


validate = validate_2004
