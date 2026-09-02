"""OCSF normalization helpers, one module per supported class.

:data:`CLASS_REGISTRY` maps an OCSF ``class_uid`` to the module that defines its
shape, enums, builders, and ``validate`` function. :func:`validate` dispatches a
finalized record to the right per-class validator.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any

from ulpf.normalize.ocsf import (
    base,
    detection_finding,
    dns_activity,
    http_activity,
    network_activity,
)

CLASS_REGISTRY: dict[int, ModuleType] = {
    network_activity.CLASS_UID: network_activity,
    detection_finding.CLASS_UID: detection_finding,
    http_activity.CLASS_UID: http_activity,
    dns_activity.CLASS_UID: dns_activity,
}


def validate(record: dict[str, Any]) -> list[str]:
    """Validate ``record`` against its class profile (dispatched via ``class_uid``)."""
    class_uid = record.get("class_uid")
    module = CLASS_REGISTRY.get(class_uid) if isinstance(class_uid, int) else None
    if module is None:
        return [f"unknown or missing class_uid: {class_uid!r}"]
    return module.validate(record)  # type: ignore[no-any-return]


__all__ = [
    "CLASS_REGISTRY",
    "base",
    "detection_finding",
    "dns_activity",
    "http_activity",
    "network_activity",
    "validate",
]
