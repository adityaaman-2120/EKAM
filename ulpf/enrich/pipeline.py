"""Run a chain of enrichers over a normalized record — safely and within budget.

:class:`EnrichmentPipeline` applies its :class:`~ulpf.enrich.base.Enricher` list
**in order**, merging each one's output under the record's ``"enrichments"``
key. It is the component that *enforces* the guarantees documented in
:mod:`ulpf.enrich.base`:

* each enricher runs under a hard per-enricher timeout
  (``settings.enrich.timeout_ms``), enforced by running it on a worker thread
  and abandoning the wait if it overruns;
* any failure — an exception, a timeout, or a non-dict return — is logged at
  WARNING and that enricher is skipped; the record still flows on, carrying
  whatever earlier enrichers already contributed;
* every attempt (success, failure, or timeout) is timed into
  ``ulpf_enrich_latency_seconds{enricher}``.

Python cannot force-kill a thread, so a hung enricher keeps running in the
background — the pipeline just stops waiting on it and moves on. The WARNING log
and the latency metric make a persistently hanging enricher obvious; it should
be removed from the chain.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from ulpf.config.settings import Settings
from ulpf.core.metrics import ENRICH_LATENCY
from ulpf.enrich.base import Enricher

_log = logging.getLogger(__name__)

_MIN_TIMEOUT_S = 0.001
_MAX_WORKERS = 8


class EnrichmentPipeline:
    """Applies an ordered list of enrichers to a record, each under a hard timeout."""

    def __init__(self, settings: Settings, enrichers: Iterable[Enricher]) -> None:
        """Wire the enricher chain; read the per-enricher timeout from ``settings``."""
        self._enrichers: tuple[Enricher, ...] = tuple(enrichers)
        self._timeout_ms = settings.enrich.timeout_ms
        self._timeout_s = max(self._timeout_ms / 1000, _MIN_TIMEOUT_S)
        # A pool so a single hung enricher does not starve the rest within a call;
        # abandoned (timed-out) tasks keep occupying a worker until they return.
        self._executor = ThreadPoolExecutor(
            max_workers=min(max(len(self._enrichers), 1), _MAX_WORKERS),
            thread_name_prefix="ulpf-enrich",
        )

    @property
    def enrichers(self) -> tuple[Enricher, ...]:
        """The configured enricher chain, in execution order."""
        return self._enrichers

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of ``record`` with every enricher's fields merged in.

        The input ``record`` is not mutated. Enricher failures and timeouts are
        logged and skipped — this method never raises.
        """
        merged: dict[str, Any] = dict(record.get("enrichments") or {})
        for enricher in self._enrichers:
            fields = self._run_one(enricher, record)
            if fields:
                merged.update(fields)
        return {**record, "enrichments": merged}

    def close(self) -> None:
        """Shut the worker pool down without waiting on any hung enricher."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    def __enter__(self) -> EnrichmentPipeline:
        """Support ``with EnrichmentPipeline(...) as p:``."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the worker pool on context exit."""
        self.close()

    # -- internals ------------------------------------------------------

    def _run_one(self, enricher: Enricher, record: dict[str, Any]) -> dict[str, Any]:
        """Run one enricher under the hard timeout; return its fields, or ``{}``."""
        name = getattr(enricher, "name", None) or type(enricher).__name__
        start = time.perf_counter()
        future: Future[Any] = self._executor.submit(enricher.enrich, record)
        try:
            result = future.result(timeout=self._timeout_s)
        except FutureTimeoutError:
            future.cancel()
            _log.warning(
                "enricher %r exceeded %d ms; skipped for this event", name, self._timeout_ms
            )
            return {}
        except Exception as exc:  # noqa: BLE001 - one bad enricher must never fail the event
            _log.warning(
                "enricher %r raised %s; skipped for this event: %s",
                name,
                type(exc).__name__,
                exc,
            )
            return {}
        finally:
            ENRICH_LATENCY.labels(enricher=name).observe(time.perf_counter() - start)

        if not isinstance(result, dict):
            _log.warning(
                "enricher %r returned %s, expected a dict; skipped", name, type(result).__name__
            )
            return {}
        return result
