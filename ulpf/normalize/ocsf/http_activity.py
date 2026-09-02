"""OCSF **HTTP Activity** (class_uid 4002, category_uid 4), schema 1.5.0.

Proxy, WAF, and reverse-proxy access logs. Same layout as
:mod:`ulpf.normalize.ocsf.network_activity`. ``activity_id`` is derived from the
HTTP method via :func:`activity_id_for_method`.

KNOWN GAPS (limitations of the standard, not of this code):

* **TLS/SNI details.** A WAF logs the negotiated cipher, TLS version, and SNI
  host; OCSF HTTP Activity has ``tls`` as an optional object but proxies rarely
  fill all of it — leftover TLS fields go to ``unmapped``.
* **WAF verdict specifics.** The matched WAF rule id, the anomaly score, and the
  paranoia level (ModSecurity/CRS) have no first-class fields; they go to
  ``unmapped`` (with ``action_id``/``disposition`` carrying the decision).
"""

from __future__ import annotations

from typing import Any

from ulpf.normalize.ocsf.base import check_class, check_enum, check_required, strip_none

CLASS_UID = 4002
CATEGORY_UID = 4

ACTIVITY_IDS: dict[int, str] = {
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
}
METHOD_ACTIVITY_IDS: dict[str, int] = {
    "CONNECT": 1,
    "DELETE": 2,
    "GET": 3,
    "HEAD": 4,
    "OPTIONS": 5,
    "POST": 6,
    "PUT": 7,
    "TRACE": 8,
}

HTTP_REQUEST_KEYS: tuple[str, ...] = ("url", "http_method", "user_agent", "referrer", "version")
HTTP_RESPONSE_KEYS: tuple[str, ...] = ("code", "length")
URL_KEYS: tuple[str, ...] = ("url_string", "scheme", "hostname", "port", "path", "query_string")

_REQUIRED_SCALAR: tuple[str, ...] = (
    "class_uid",
    "category_uid",
    "activity_id",
    "type_uid",
    "severity_id",
    "time",
)
_REQUIRED_OBJECT: tuple[str, ...] = ("metadata", "http_request", "src_endpoint")
REQUIRED_4002: tuple[str, ...] = _REQUIRED_SCALAR + _REQUIRED_OBJECT
RECOMMENDED_4002: tuple[str, ...] = (
    "http_response",
    "dst_endpoint",
    "status_id",
    "severity",
    "activity_name",
    "type_name",
    "unmapped",
)

CLASS_SHAPE: dict[str, Any] = {
    "class_uid": CLASS_UID,
    "category_uid": CATEGORY_UID,
    "required": REQUIRED_4002,
    "recommended": RECOMMENDED_4002,
    "objects": {
        "http_request": HTTP_REQUEST_KEYS,
        "http_response": HTTP_RESPONSE_KEYS,
        "url": URL_KEYS,
    },
    "enums": {"activity_id": ACTIVITY_IDS},
}


def activity_id_for_method(method: str | None) -> int:
    """Map an HTTP method name to its OCSF ``activity_id`` (unknown -> 99 Other)."""
    return METHOD_ACTIVITY_IDS.get((method or "").strip().upper(), 99)


def build_url(
    *,
    text: str | None = None,
    scheme: str | None = None,
    hostname: str | None = None,
    port: int | None = None,
    path: str | None = None,
    query_string: str | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``url`` object (``text`` -> ``url_string``), omitting unset fields."""
    return strip_none(
        {
            "url_string": text,
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query_string": query_string,
        }
    )


def build_http_request(
    *,
    url: str | dict[str, Any] | None = None,
    http_method: str | None = None,
    user_agent: str | None = None,
    referrer: str | None = None,
    version: str | None = None,
) -> dict[str, Any]:
    """Build an OCSF ``http_request`` object, omitting unset fields."""
    return strip_none(
        {
            "url": url,
            "http_method": http_method,
            "user_agent": user_agent,
            "referrer": referrer,
            "version": version,
        }
    )


def build_http_response(*, code: int | None = None, length: int | None = None) -> dict[str, Any]:
    """Build an OCSF ``http_response`` object, omitting unset fields."""
    return strip_none({"code": code, "length": length})


def new_record(
    *,
    activity_id: int,
    severity_id: int,
    time: int,
    metadata: dict[str, Any],
    http_request: dict[str, Any],
    src_endpoint: dict[str, Any],
    dst_endpoint: dict[str, Any] | None = None,
    http_response: dict[str, Any] | None = None,
    status_id: int | None = None,
    unmapped: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble an HTTP Activity record. Run ``ocsf.base.finalize`` after."""
    return strip_none(
        {
            "class_uid": CLASS_UID,
            "category_uid": CATEGORY_UID,
            "activity_id": activity_id,
            "activity_name": ACTIVITY_IDS.get(activity_id),
            "severity_id": severity_id,
            "time": time,
            "metadata": metadata,
            "http_request": http_request,
            "http_response": http_response,
            "src_endpoint": src_endpoint,
            "dst_endpoint": dst_endpoint,
            "status_id": status_id,
            "unmapped": unmapped,
        }
    )


def validate_4002(record: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the record satisfies the 4002 profile."""
    problems = check_required(record, scalars=_REQUIRED_SCALAR, objects=_REQUIRED_OBJECT)
    problems += check_class(record, CLASS_UID, CATEGORY_UID)
    problems += check_enum(record, "activity_id", ACTIVITY_IDS, label="HTTP Activity value")
    return problems


validate = validate_4002
