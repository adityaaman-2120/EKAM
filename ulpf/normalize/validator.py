"""OCSF record validation and the normalization-completeness KPI.

:class:`OcsfValidator` checks a finalized OCSF record against its class profile
and reports a **completeness** score — the fraction of the class's
required + recommended attributes that were actually populated. That score is
the "normalization completeness %" KPI and is also recorded, per event, into the
``ulpf_normalization_completeness`` histogram.

Checks performed:

* ``class_uid`` present and known (in :data:`~ulpf.normalize.ocsf.CLASS_REGISTRY`);
* the class's own ``validate`` function (required attributes, ``category_uid``
  match, enum membership, class-specific rules);
* ``type_uid`` equals ``class_uid * 100 + activity_id`` when present;
* ``time`` is a positive ``int`` when present;
* every nested ``ip`` field parses as an IP address;
* every nested ``port`` field is an integer in ``0..65535``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from ulpf.core.metrics import NORMALIZATION_COMPLETENESS
from ulpf.normalize.ocsf import CLASS_REGISTRY

_PORT_MIN = 0
_PORT_MAX = 65535


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of validating one OCSF record."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    completeness: float


class OcsfValidator:
    """Validates finalized OCSF records and scores their normalization completeness."""

    def __init__(self, *, record_metrics: bool = True) -> None:
        """Create a validator.

        Args:
            record_metrics: When true (default), every :meth:`validate` call
                observes the completeness score into
                ``ulpf_normalization_completeness``.
        """
        self._record_metrics = record_metrics

    def validate(self, record: dict[str, Any]) -> ValidationResult:
        """Validate ``record`` and return a :class:`ValidationResult`."""
        errors: list[str] = []
        warnings: list[str] = []

        class_uid = record.get("class_uid")
        module = CLASS_REGISTRY.get(class_uid) if isinstance(class_uid, int) else None
        if module is None:
            errors.append(f"unknown or missing class_uid: {class_uid!r}")
            return self._finish(errors, warnings, 0.0)

        errors.extend(module.validate(record))
        self._check_type_uid(record, errors)
        self._check_time(record, errors)
        self._check_ips(record, errors)
        self._check_ports(record, errors)
        self._collect_warnings(record, warnings)

        completeness = _completeness(module, record)
        return self._finish(errors, warnings, completeness)

    def _finish(
        self, errors: list[str], warnings: list[str], completeness: float
    ) -> ValidationResult:
        """Record the completeness metric (if enabled) and build the result."""
        if self._record_metrics:
            NORMALIZATION_COMPLETENESS.observe(completeness)
        return ValidationResult(
            valid=not errors, errors=errors, warnings=warnings, completeness=completeness
        )

    @staticmethod
    def _check_type_uid(record: dict[str, Any], errors: list[str]) -> None:
        """``type_uid`` must equal ``class_uid * 100 + activity_id`` when present."""
        type_uid = record.get("type_uid")
        class_uid = record.get("class_uid")
        activity_id = record.get("activity_id")
        if type_uid is None or not isinstance(class_uid, int) or not isinstance(activity_id, int):
            return
        expected = class_uid * 100 + activity_id
        if type_uid != expected:
            errors.append(f"type_uid {type_uid!r} should be {expected}")

    @staticmethod
    def _check_time(record: dict[str, Any], errors: list[str]) -> None:
        """``time`` must be a positive ``int`` when present (absence is a per-class error)."""
        if "time" not in record or record["time"] is None:
            return
        value = record["time"]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            errors.append(f"time must be a positive int, got {value!r}")

    @staticmethod
    def _check_ips(record: dict[str, Any], errors: list[str]) -> None:
        """Every nested ``ip`` value must parse as an IPv4/IPv6 address."""
        for value in _collect(record, "ip"):
            try:
                ipaddress.ip_address(str(value).strip())
            except ValueError:
                errors.append(f"invalid IP address: {value!r}")

    @staticmethod
    def _check_ports(record: dict[str, Any], errors: list[str]) -> None:
        """Every nested ``port`` value must be an integer in ``0..65535``."""
        for value in _collect(record, "port"):
            port = _as_port(value)
            if port is None or not (_PORT_MIN <= port <= _PORT_MAX):
                errors.append(f"port out of range {_PORT_MIN}-{_PORT_MAX}: {value!r}")

    @staticmethod
    def _collect_warnings(record: dict[str, Any], warnings: list[str]) -> None:
        """Soft issues that do not fail validation but hint at an incomplete mapping."""
        metadata = record.get("metadata")
        if not (isinstance(metadata, dict) and metadata.get("version")):
            warnings.append("metadata.version is not set")
        if record.get("activity_id") == 0:
            warnings.append("activity_id is 0 (Unknown)")
        if record.get("severity_id") == 0:
            warnings.append("severity_id is 0 (Unknown)")


def _completeness(module: ModuleType, record: dict[str, Any]) -> float:
    """Populated (required + recommended) attributes / total, in ``[0, 1]``."""
    shape = module.CLASS_SHAPE
    attrs = list(dict.fromkeys([*shape["required"], *shape["recommended"]]))
    if not attrs:
        return 0.0
    populated = sum(1 for attr in attrs if _is_populated(record.get(attr)))
    return populated / len(attrs)


def _is_populated(value: Any) -> bool:
    """Whether an attribute counts as filled (``0``/``False`` do; empty str/dict/list don't)."""
    if value is None:
        return False
    if isinstance(value, (str, dict, list)) and len(value) == 0:
        return False
    return True


def _as_port(value: Any) -> int | None:
    """Coerce a port value to ``int`` (accepting digit strings); ``None`` if not numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _collect(obj: Any, key: str) -> list[Any]:
    """All scalar values stored under ``key`` anywhere in a nested dict/list structure."""
    found: list[Any] = []
    if isinstance(obj, dict):
        for name, value in obj.items():
            if name == key and not isinstance(value, (dict, list)):
                found.append(value)
            else:
                found.extend(_collect(value, key))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_collect(item, key))
    return found
