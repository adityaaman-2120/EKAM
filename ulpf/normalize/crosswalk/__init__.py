"""Crosswalks from the canonical OCSF record to other schemas.

ULPF normalizes every perimeter event to OCSF 1.5.0 (the canonical, lossless
form). A *crosswalk* is a lossy, best-effort projection of that record onto
another well-known schema so ULPF can feed tools that expect it:

* :mod:`ulpf.normalize.crosswalk.ecs` -> Elastic Common Schema, for Elastic /
  OpenSearch data streams and detection rules.
* :mod:`ulpf.normalize.crosswalk.cim` -> Splunk Common Information Model, for
  Splunk searches and accelerated data models.

Crosswalks never mutate the OCSF record; they read it and return a new dict.
"""

from __future__ import annotations

from ulpf.normalize.crosswalk.cim import to_cim
from ulpf.normalize.crosswalk.ecs import to_ecs

__all__ = ["to_cim", "to_ecs"]
