"""Enrichment layer — contract and hard design rules.

Enrichment adds context to a normalized OCSF record (geolocation of an address,
whether an IP is a known indicator of compromise, asset owner, ASN, ...) *after*
normalization and *before* the record reaches the sinks.

NON-NEGOTIABLE: **enrichment must NEVER block the hot path.**

* Every lookup is **in-memory**, against data **pre-loaded once at startup** — a
  memory-mapped MMDB opened at boot, a ``frozenset`` of IOC strings, a dict of
  asset records. An enricher never reads a file, opens a socket, or calls a
  service *per event*.
* **No runtime network calls.** ULPF ships as an air-gapped container: there is
  no DNS, no WHOIS, no threat-intel API available at run time. Reference data
  arrives on disk with the deployment and is refreshed out of band.
* Every enricher runs under a **hard timeout** (``settings.enrich.timeout_ms``).
  If it overruns, it is skipped for that event — the event is never delayed and
  never dropped. See :class:`~ulpf.enrich.pipeline.EnrichmentPipeline`.
* Every enricher has a **defined fallback**: absent reference data or a lookup
  miss yields an empty dict, not an error.

An :class:`Enricher` returns only the fields it wants merged under the record's
``"enrichments"`` key and never mutates the record it is handed.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ulpf.core.errors import UlpfError

# What an enricher returns: a flat mapping merged under ``record["enrichments"]``.
EnrichmentFields = dict[str, Any]


class EnricherError(UlpfError):
    """An enricher could not produce enrichment for this event.

    Raising this — or any other exception — makes
    :class:`~ulpf.enrich.pipeline.EnrichmentPipeline` log the failure and skip
    this enricher for this event. It never fails or drops the event.
    """


@runtime_checkable
class Enricher(Protocol):
    """Adds context fields to a normalized record from pre-loaded, in-memory data."""

    name: str

    def enrich(self, record: dict[str, Any]) -> EnrichmentFields:
        """Return the fields to merge under ``record["enrichments"]``.

        Must be non-blocking — pure in-memory lookups only, no I/O. Return an
        empty dict on a lookup miss or when reference data is unavailable (the
        defined fallback). Must not mutate ``record``.
        """
        ...
