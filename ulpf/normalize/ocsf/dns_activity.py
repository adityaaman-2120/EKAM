"""OCSF **DNS Activity** (class_uid 4003, category_uid 4), schema 1.5.0.

DNS proxy / resolver / passive-DNS logs. Same layout as
:mod:`ulpf.normalize.ocsf.network_activity`.

KNOWN GAPS (limitations of the standard, not of this code):

* **EDNS / DNSSEC.** OPT pseudo-record options, the DO bit, UDP payload size,
  and per-answer DNSSEC validation state have no first-class fields on
  ``dns_query``/``dns_answer``; they go to ``unmapped``.
* **Transport port for the resolver.** OCSF models the answer set but not always
  the exact resolver source port used (relevant for cache-poisoning analysis);
  keep it in ``src_endpoint``/``dst_endpoint`` or ``unmapped``.
"""

from __future__ import annotations

from typing import Any

from ulpf.normalize.ocsf.base import check_class, check_enum, check_required, strip_none

CLASS_UID = 4003
CATEGORY_UID = 4

ACTIVITY_IDS: dict[int, str] = {
    0: "Unknown",
    1: "Query",
    2: "Response",
    6: "Traffic",
    99: "Other",
}
RCODE_IDS: dict[int, str] = {
    0: "NoError",
    1: "FormError",
    2: "ServError",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
    99: "Other",
}

QUERY_KEYS: tuple[str, ...] = ("hostname", "type", "class")
ANSWER_KEYS: tuple[str, ...] = ("rdata", "type", "class", "ttl", "flag_ids")

_REQUIRED_SCALAR: tuple[str, ...] = (
    "class_uid",
    "category_uid",
    "activity_id",
    "type_uid",
    "severity_id",
    "time",
)
_REQUIRED_OBJECT: tuple[str, ...] = ("metadata", "query", "src_endpoint")
REQUIRED_4003: tuple[str, ...] = _REQUIRED_SCALAR + _REQUIRED_OBJECT
RECOMMENDED_4003: tuple[str, ...] = (
    "dst_endpoint",
    "answers",
    "rcode",
    "rcode_id",
    "response_time",
    "status_id",
    "severity",
    "activity_name",
    "type_name",
    "unmapped",
)

CLASS_SHAPE: dict[str, Any] = {
    "class_uid": CLASS_UID,
    "category_uid": CATEGORY_UID,
    "required": REQUIRED_4003,
    "recommended": RECOMMENDED_4003,
    "objects": {"query": QUERY_KEYS, "answers": ANSWER_KEYS},
    "enums": {"activity_id": ACTIVITY_IDS, "rcode_id": RCODE_IDS},
}


def build_query(
    *, hostname: str | None = None, type_: str | None = None, class_: str | None = None
) -> dict[str, Any]:
    """Build an OCSF ``dns_query`` object, omitting unset fields."""
    return strip_none({"hostname": hostname, "type": type_, "class": class_})


def build_answer(
    *,
    rdata: str | None = None,
    type_: str | None = None,
    class_: str | None = None,
    ttl: int | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``dns_answer`` object, omitting unset fields."""
    return strip_none({"rdata": rdata, "type": type_, "class": class_, "ttl": ttl})


def new_record(
    *,
    activity_id: int,
    severity_id: int,
    time: int,
    metadata: dict[str, Any],
    query: dict[str, Any],
    src_endpoint: dict[str, Any],
    dst_endpoint: dict[str, Any] | None = None,
    answers: list[dict[str, Any]] | None = None,
    rcode_id: int | None = None,
    response_time: int | None = None,
    status_id: int | None = None,
    unmapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a DNS Activity record. Run ``ocsf.base.finalize`` after."""
    return strip_none(
        {
            "class_uid": CLASS_UID,
            "category_uid": CATEGORY_UID,
            "activity_id": activity_id,
            "activity_name": ACTIVITY_IDS.get(activity_id),
            "severity_id": severity_id,
            "time": time,
            "metadata": metadata,
            "query": query,
            "answers": answers,
            "rcode_id": rcode_id,
            "rcode": RCODE_IDS.get(rcode_id) if rcode_id is not None else None,
            "response_time": response_time,
            "src_endpoint": src_endpoint,
            "dst_endpoint": dst_endpoint,
            "status_id": status_id,
            "unmapped": unmapped,
        }
    )


def validate_4003(record: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the record satisfies the 4003 profile."""
    problems = check_required(record, scalars=_REQUIRED_SCALAR, objects=_REQUIRED_OBJECT)
    problems += check_class(record, CLASS_UID, CATEGORY_UID)
    problems += check_enum(record, "activity_id", ACTIVITY_IDS, label="DNS Activity value")
    problems += check_enum(record, "rcode_id", RCODE_IDS, label="valid rcode_id")
    return problems


validate = validate_4003
