"""Optional OpenSearch / Elasticsearch sink — bulk-indexes the ECS crosswalk.

Streams :func:`~ulpf.normalize.crosswalk.ecs.to_ecs`'s output (**not** the raw
OCSF record — this sink is for teams already standardised on ECS dashboards) to
a daily index ``<index_prefix>-YYYY.MM.DD`` (default ``ulpf-ecs-YYYY.MM.DD``),
matching the Beats/ECS convention so existing Kibana content and ILM policies
apply unchanged.

FAIL SOFT — THE DEMO NEVER BREAKS BECAUSE AN OPTIONAL SINK IS DOWN
-------------------------------------------------------------------
OpenSearch is an *optional* export, never a dependency of the core pipeline.
:meth:`OpenSearchSink.start` pings the cluster; if it is unreachable the sink
logs a warning and **disables itself for the run** — every :meth:`write` /
:meth:`flush` afterwards is then a silent no-op, so nothing upstream ever
blocks or errors because this service happens to be down. Unlike
:class:`~ulpf.sinks.clickhouse_sink.ClickHouseSink`, a batch that keeps failing
mid-run is logged and dropped after retrying — this sink never applies
backpressure and never spools to disk. Use ClickHouse when delivery must be
guaranteed; use this when a nice-to-have ECS view is enough.

INDEX TEMPLATE
    Created (best-effort; a failure here does not disable the sink — new
    indices just fall back to dynamic mapping) once at :meth:`start`, mapping
    the ECS field types used by the crosswalk: IP fields as ``ip`` (enables
    CIDR queries), ports/bytes/severity as ``long``, and the rest as
    ``keyword``.

BULK API
    ``POST /_bulk`` with NDJSON action/document pairs, batched at
    ``batch_docs`` (default 500) or ``batch_seconds`` (default 5). Each
    document is indexed with ``_id = event_uid``, so a retried/duplicated
    write overwrites the same document instead of creating a second one.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ulpf.config.settings import Settings
from ulpf.core.models import NormalizedEvent
from ulpf.normalize.crosswalk.ecs import to_ecs
from ulpf.sinks._delivery import FatalDeliveryError, RetryableDeliveryError, deliver_with_retry

_log = logging.getLogger(__name__)

_INDEX_TEMPLATE_MAPPING: dict[str, Any] = {
    "index_patterns": [],  # filled in from index_prefix at creation time
    "template": {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "ecs": {"properties": {"version": {"type": "keyword"}}},
                "event": {
                    "properties": {
                        "kind": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "severity": {"type": "long"},
                        "id": {"type": "keyword"},
                    }
                },
                "source": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "long"},
                        "bytes": {"type": "long"},
                        "mac": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "nat": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                    }
                },
                "destination": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "port": {"type": "long"},
                        "bytes": {"type": "long"},
                        "mac": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "nat": {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}},
                    }
                },
                "network": {
                    "properties": {
                        "transport": {"type": "keyword"},
                        "iana_number": {"type": "long"},
                        "bytes": {"type": "long"},
                    }
                },
                "rule": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "id": {"type": "keyword"},
                        "category": {"type": "keyword"},
                    }
                },
                "observer": {
                    "properties": {
                        "vendor": {"type": "keyword"},
                        "product": {"type": "keyword"},
                        "ingress": {"properties": {"zone": {"type": "keyword"}}},
                        "egress": {"properties": {"zone": {"type": "keyword"}}},
                    }
                },
                "related": {"properties": {"ip": {"type": "ip"}}},
            }
        }
    },
}


class OpenSearchSink:
    """Bulk-indexes the ECS crosswalk of each event into daily OpenSearch indices."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Configure from ``settings.opensearch``; ``client``/``clock``/``sleep`` are injectable."""
        cfg = settings.opensearch
        self._cfg = cfg
        self._configured = bool(cfg.enabled)
        self._enabled = False  # flips true in start() only after a successful health check
        self._base_url = cfg.url.rstrip("/") + "/"

        self._client = client
        self._owns_client = client is None
        self._clock = clock
        self._sleep = sleep

        self._buffer: list[tuple[str, str, dict[str, Any]]] = []  # (index, doc_id, doc)
        self._started = False
        self._closed = False
        self._timer: asyncio.Task[None] | None = None
        self.docs_indexed = 0
        self.docs_dropped = 0
        self.batches_dropped = 0

    # -- lifecycle ----------------------------------------------------

    async def start(self, *, timer: bool = True) -> None:
        """Health-check the cluster; self-disable (log + no-op forever) if unreachable."""
        if not self._configured or self._started:
            return
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self._cfg.request_timeout_seconds, verify=self._cfg.verify_tls
            )
        self._enabled = await self._health_check()
        if not self._enabled:
            _log.warning(
                "OpenSearch at %s is unreachable; the sink is DISABLED for this run "
                "(the pipeline continues without it)",
                self._cfg.url,
            )
        else:
            await self._ensure_index_template()
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
        """Buffer one event's ECS document; flush at ``batch_docs``. A no-op when disabled."""
        if not self._enabled:
            return
        doc = to_ecs(event.ocsf)
        index = _index_name(self._cfg.index_prefix, doc.get("@timestamp"), event.ingest_time_ns)
        self._buffer.append((index, event.event_uid, doc))
        if len(self._buffer) >= self._cfg.batch_docs:
            await self._drain_once()

    async def flush(self) -> None:
        """Deliver every buffered document (each failing batch is logged and dropped)."""
        while self._enabled and self._buffer:
            await self._drain_once()

    @property
    def pending_docs(self) -> int:
        """Documents buffered but not yet sent."""
        return len(self._buffer)

    # -- delivery -----------------------------------------------

    async def _drain_once(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[: self._cfg.batch_docs]
        del self._buffer[: len(batch)]
        body = _bulk_body(batch)

        async def _send() -> None:
            await self._bulk_request(body)

        def _on_fail(attempt: int, exc: Exception, fatal: bool) -> None:
            _log.warning(
                "OpenSearch bulk attempt %d failed (%s): %s",
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
            self.docs_indexed += len(batch)
        else:
            self.docs_dropped += len(batch)
            self.batches_dropped += 1
            _log.error("OpenSearch: dropping a batch of %d documents after retries", len(batch))

    async def _bulk_request(self, body: str) -> None:
        assert self._client is not None
        try:
            response = await self._client.post(
                self._base_url + "_bulk",
                content=body,
                headers={**self._auth_headers(), "Content-Type": "application/x-ndjson"},
            )
        except httpx.HTTPError as exc:
            raise RetryableDeliveryError(f"transport error: {exc}") from exc
        if response.status_code >= 300:
            detail = response.text[:300]
            if response.status_code == 429 or response.status_code >= 500:
                raise RetryableDeliveryError(f"HTTP {response.status_code}: {detail}")
            raise FatalDeliveryError(f"HTTP {response.status_code}: {detail}")
        payload = response.json()
        if payload.get("errors"):
            _log_item_errors(payload)

    async def _health_check(self) -> bool:
        assert self._client is not None
        try:
            response = await self._client.get(self._base_url, headers=self._auth_headers())
        except httpx.HTTPError as exc:
            _log.warning("OpenSearch health check failed: %s", exc)
            return False
        return response.status_code < 300

    async def _ensure_index_template(self) -> None:
        assert self._client is not None
        name = f"{self._cfg.index_prefix}-template"
        body = dict(_INDEX_TEMPLATE_MAPPING)
        body["index_patterns"] = [f"{self._cfg.index_prefix}-*"]
        try:
            response = await self._client.put(
                f"{self._base_url}_index_template/{name}",
                json=body,
                headers=self._auth_headers(),
            )
            if response.status_code >= 300:
                _log.warning(
                    "could not create OpenSearch index template %s (HTTP %d); "
                    "new indices will use dynamic mapping",
                    name,
                    response.status_code,
                )
        except httpx.HTTPError as exc:
            _log.warning("could not create OpenSearch index template %s: %s", name, exc)

    def _auth_headers(self) -> dict[str, str]:
        if self._cfg.api_key:
            return {"Authorization": f"ApiKey {self._cfg.api_key}"}
        if self._cfg.user:
            import base64

            token = base64.b64encode(
                f"{self._cfg.user}:{self._cfg.password or ''}".encode()
            ).decode()
            return {"Authorization": f"Basic {token}"}
        return {}

    async def _timer_loop(self) -> None:
        try:
            while not self._closed:
                await self._sleep(self._cfg.batch_seconds)
                if self._buffer:
                    await self._drain_once()
        except asyncio.CancelledError:
            pass


def _index_name(prefix: str, iso_timestamp: Any, fallback_ns: int) -> str:
    """``<prefix>-YYYY.MM.DD`` from an ECS ``@timestamp`` string, or the ingest time."""
    if isinstance(iso_timestamp, str) and iso_timestamp:
        with contextlib.suppress(ValueError):
            moment = dt.datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
            return f"{prefix}-{moment.strftime('%Y.%m.%d')}"
    seconds = fallback_ns // 1_000_000_000
    moment = dt.datetime.fromtimestamp(seconds, dt.UTC)
    return f"{prefix}-{moment.strftime('%Y.%m.%d')}"


def _bulk_body(batch: list[tuple[str, str, dict[str, Any]]]) -> str:
    """NDJSON action+document pairs for the ``_bulk`` API."""
    lines: list[str] = []
    for index, doc_id, doc in batch:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}, separators=(",", ":")))
        lines.append(json.dumps(doc, separators=(",", ":"), default=str))
    return "\n".join(lines) + "\n"


def _log_item_errors(payload: dict[str, Any]) -> None:
    """Log the individual document failures from a partially-failed bulk response."""
    failed = [
        item["index"]
        for item in payload.get("items", [])
        if "index" in item and item["index"].get("status", 200) >= 300
    ]
    if failed:
        _log.warning(
            "OpenSearch bulk: %d/%d documents rejected, e.g. %s",
            len(failed),
            len(payload.get("items", [])),
            failed[0].get("error"),
        )
