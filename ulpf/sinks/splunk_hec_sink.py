"""Optional Splunk HTTP Event Collector sink — posts the CIM crosswalk.

Streams :func:`~ulpf.normalize.crosswalk.cim.to_cim`'s output (Splunk Common
Information Model fields + ``tags``, **not** the raw OCSF record) to a Splunk
HEC endpoint, one event per source event, with ``sourcetype`` set to the
event's ``source_type`` (e.g. ``fortigate_traffic``, ``suricata_eve_alert``) so
CIM-aware Splunk apps and accelerated data models pick it up without extra
props/transforms configuration.

FAIL SOFT — THE DEMO NEVER BREAKS BECAUSE AN OPTIONAL SINK IS DOWN
-------------------------------------------------------------------
Splunk is an optional export. :meth:`SplunkHecSink.start` calls HEC's own
``/services/collector/health`` endpoint; if it does not answer healthy the sink
logs a warning and **disables itself for the run** (:meth:`write` / :meth:`flush`
become silent no-ops). Like :mod:`ulpf.sinks.opensearch_sink` (and unlike
:class:`~ulpf.sinks.clickhouse_sink.ClickHouseSink`) a batch that still fails
after retrying is logged and dropped rather than applying backpressure or
spooling — this sink never blocks the pipeline.

AUTH & BATCHING
    Bearer-style token auth (``Authorization: Splunk <token>`` from
    ``settings.splunk_hec.token``) against ``POST /services/collector/event``,
    batched at ``batch_events`` (default 100) or ``batch_seconds`` (default 5).
    Multiple HEC event envelopes are concatenated in one request body — HEC's
    JSON parser reads consecutive top-level objects from a single POST.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ulpf.config.settings import Settings
from ulpf.core.models import NormalizedEvent
from ulpf.normalize.crosswalk.cim import to_cim
from ulpf.sinks._delivery import FatalDeliveryError, RetryableDeliveryError, deliver_with_retry

_log = logging.getLogger(__name__)

_HEALTH_PATH = "services/collector/health"
_EVENT_PATH = "services/collector/event"


class SplunkHecSink:
    """Batches events as the CIM crosswalk and posts them to Splunk HEC."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Configure from ``settings.splunk_hec``; ``client``/``clock``/``sleep`` are injectable."""
        cfg = settings.splunk_hec
        self._cfg = cfg
        self._configured = bool(cfg.enabled)
        self._enabled = False  # flips true in start() only after a healthy /health check

        self._client = client
        self._owns_client = client is None
        self._clock = clock
        self._sleep = sleep

        self._buffer: list[dict[str, Any]] = []
        self._started = False
        self._closed = False
        self._timer: asyncio.Task[None] | None = None
        self.events_delivered = 0
        self.events_dropped = 0
        self.batches_dropped = 0

    # -- lifecycle ----------------------------------------------------

    async def start(self, *, timer: bool = True) -> None:
        """Check HEC's health endpoint; self-disable (log + no-op forever) if it is not healthy."""
        if not self._configured or self._started:
            return
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._cfg.request_timeout_seconds, verify=self._cfg.verify_tls
            )
        self._enabled = await self._health_check()
        if not self._enabled:
            _log.warning(
                "Splunk HEC at %s is unreachable/unhealthy; the sink is DISABLED for this run "
                "(the pipeline continues without it)",
                self._cfg.url,
            )
        self._started = True
        self._closed = False
        if timer and self._enabled:
            self._timer = asyncio.ensure_future(self._timer_loop())

    async def close(self) -> None:
        """Stop the timer, flush what we can (best effort, never blocks), close the client."""
        if not self._started:
            return
        self._closed = True
        if self._timer is not None:
            self._timer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._timer
            self._timer = None
        if self._enabled:
            await self.flush()
        if self._owns_client and self._client is not None:
            await self._client.aclose()
        self._started = False

    # -- writing ----------------------------------------------------

    async def write(self, event: NormalizedEvent) -> None:
        """Buffer one event's CIM envelope; flush at ``batch_events``. A no-op when disabled."""
        if not self._enabled:
            return
        self._buffer.append(_hec_envelope(event, self._cfg.source, self._cfg.host, self._cfg.index))
        if len(self._buffer) >= self._cfg.batch_events:
            await self._drain_once()

    async def flush(self) -> None:
        """Deliver every buffered event (a failing batch is logged and dropped)."""
        while self._enabled and self._buffer:
            await self._drain_once()

    @property
    def pending_events(self) -> int:
        """Events buffered but not yet sent."""
        return len(self._buffer)

    # -- delivery -----------------------------------------------

    async def _drain_once(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[: self._cfg.batch_events]
        del self._buffer[: len(batch)]
        body = "\n".join(json.dumps(env, separators=(",", ":"), default=str) for env in batch)

        async def _send() -> None:
            await self._post_events(body)

        def _on_fail(attempt: int, exc: Exception, fatal: bool) -> None:
            _log.warning(
                "Splunk HEC attempt %d failed (%s): %s",
                attempt + 1,
                "fatal" if fatal else "retrying",
                exc,
            )

        delivered = await deliver_with_retry(
            _send,
            max_retries=self._cfg.max_retries,
            backoff_base_seconds=self._cfg.backoff_base_seconds,
            backoff_max_seconds=self._cfg.backoff_max_seconds,
            sleep=self._sleep,
            on_attempt_failed=_on_fail,
        )
        if delivered:
            self.events_delivered += len(batch)
        else:
            self.events_dropped += len(batch)
            self.batches_dropped += 1
            _log.error("Splunk HEC: dropping a batch of %d events after retries", len(batch))

    async def _post_events(self, body: str) -> None:
        assert self._client is not None
        try:
            response = await self._client.post(
                self._url(_EVENT_PATH), content=body, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise RetryableDeliveryError(f"transport error: {exc}") from exc
        if response.status_code < 300:
            return
        detail = response.text[:300]
        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableDeliveryError(f"HTTP {response.status_code}: {detail}")
        raise FatalDeliveryError(f"HTTP {response.status_code}: {detail}")

    async def _health_check(self) -> bool:
        assert self._client is not None
        try:
            response = await self._client.get(self._url(_HEALTH_PATH), headers=self._headers())
        except httpx.HTTPError as exc:
            _log.warning("Splunk HEC health check failed: %s", exc)
            return False
        return response.status_code == 200

    def _url(self, path: str) -> str:
        return self._cfg.url.rstrip("/") + "/" + path

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Splunk {self._cfg.token}", "Content-Type": "application/json"}

    async def _timer_loop(self) -> None:
        try:
            while not self._closed:
                await self._sleep(self._cfg.batch_seconds)
                if self._buffer:
                    await self._drain_once()
        except asyncio.CancelledError:
            pass


def _hec_envelope(
    event: NormalizedEvent, source: str, host: str, index: str | None
) -> dict[str, Any]:
    """One HEC event object: metadata envelope + the CIM crosswalk as ``event``."""
    epoch_ns = event.ocsf.get("time") or event.ingest_time_ns
    envelope: dict[str, Any] = {
        "time": epoch_ns / 1_000_000_000,
        "host": host,
        "source": source,
        "sourcetype": event.source_type or "unknown",
        "event": to_cim(event.ocsf),
    }
    if index:
        envelope["index"] = index
    return envelope
