"""Optional ClickHouse sink — batched, retrying, back-pressuring, never-dropping.

ULPF works with **no** ClickHouse (Parquet lake + in-memory DuckDB). When one
*is* configured (``settings.clickhouse.enabled``) this sink streams normalized
events into it over the plain **HTTP interface** (no extra driver — ``httpx``,
already a dependency), using the native ``JSONEachRow`` insert format.

TABLE (created on start if absent)
    ``ReplacingMergeTree`` — so that the at-least-once duplicates an upstream
    retry can produce collapse on merge (rows with an equal sorting key are
    de-duplicated). The sorting key ends in ``event_uid``, and duplicates of one
    event are byte-identical on ``(time, source_type, event_uid)``.
    ``PARTITION BY toYYYYMMDD(<time>)`` for cheap day pruning / TTL.
    Columns are the Parquet silver schema's 17 core columns, plus ``unmapped``
    and ``enrichments`` as ``String`` (JSON).

DELIVERY GUARANTEES
    * **Batched** — flush at ``batch_rows`` (5000) or ``batch_seconds`` (5).
    * **Retried** — transport errors and 5xx/429 retry with exponential backoff
      (``backoff_base`` .. ``backoff_max``) up to ``max_retries``.
    * **Back-pressuring, never dropping** — undelivered rows stay in a bounded
      in-memory buffer; once it is full, :meth:`ClickHouseSink.write` *blocks*
      its caller (which stalls the pipeline worker, which fills the intake
      queue, which back-pressures the listeners) rather than discarding events.
    * **Spooled on shutdown** — anything still undelivered when :meth:`close` is
      called (or a non-retryable 4xx batch) is written to
      ``state_path/clickhouse_spool/*.jsonl`` and re-loaded on the next
      :meth:`start`. Nothing is ever lost.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from ulpf.config.settings import Settings
from ulpf.core.models import NormalizedEvent
from ulpf.sinks.parquet_sink import CORE_COLUMNS, core_row

_log = logging.getLogger(__name__)

_SPOOL_DIR = "clickhouse_spool"

# ClickHouse column types. The sorting-key columns are non-nullable; everything
# else mirrors the (nullable) Parquet silver schema.
_KEY_COLUMNS = ("time", "source_type", "event_uid")
_STRING_COLUMNS = frozenset(
    {"event_uid", "raw_hash", "source_type", "src_ip", "dst_ip", "protocol"}
)
_JSON_COLUMNS = ("unmapped", "enrichments")


def _column_ddl(name: str) -> str:
    base = "String" if name in _STRING_COLUMNS else "Int64"
    return f"    `{name}` {base}" if name in _KEY_COLUMNS else f"    `{name}` Nullable({base})"


class ClickHouseSink:
    """Streams :class:`NormalizedEvent`s into ClickHouse; batched, retrying, lossless."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Configure from ``settings.clickhouse``; ``client``/``clock``/``sleep`` are injectable."""
        cfg = settings.clickhouse
        self._cfg = cfg
        self._enabled = bool(cfg.enabled)
        self._base_url = cfg.url.rstrip("/") + "/"
        self._insert_head = f"INSERT INTO `{cfg.database}`.`{cfg.table}` FORMAT JSONEachRow\n"
        self._spool = Path(settings.storage.state_path) / _SPOOL_DIR

        self._client = client
        self._owns_client = client is None
        self._clock = clock
        self._sleep = sleep

        self._buffer: list[dict[str, Any]] = []
        self._started = False
        self._closed = False
        self._table_ready = False
        self._timer: asyncio.Task[None] | None = None
        self._flush_lock = asyncio.Lock()
        self._down_since: float | None = None
        self.rows_delivered = 0
        self.batches_delivered = 0
        self.rows_spooled = 0

    # -- lifecycle ----------------------------------------------------

    async def start(self, *, timer: bool = True) -> None:
        """Open the HTTP client, create the table, and reload any spooled rows.

        ``timer=False`` skips the background time-based flush loop (tests drive
        :meth:`flush` explicitly).
        """
        if not self._enabled or self._started:
            return
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._cfg.request_timeout_seconds)
        with contextlib.suppress(Exception):
            await self._ensure_table()
        self._reload_spool()
        self._closed = False
        self._started = True
        if timer:
            self._timer = asyncio.ensure_future(self._timer_loop())

    async def close(self) -> None:
        """Stop the timer, flush what we can, spool the rest, close the client."""
        if not self._enabled or not self._started:
            return
        self._closed = True
        if self._timer is not None:
            self._timer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._timer
            self._timer = None

        for _ in range(self._cfg.max_retries + 2):
            if not self._buffer:
                break
            await self._drain_once()
        if self._buffer:
            self._spool_rows(self._buffer)
            _log.error(
                "ClickHouse unreachable at shutdown; spooled %d rows to %s (nothing dropped)",
                len(self._buffer),
                self._spool,
            )
            self._buffer = []

        if self._owns_client and self._client is not None:
            await self._client.aclose()
        self._started = False

    # -- writing ----------------------------------------------------

    async def write(self, event: NormalizedEvent) -> None:
        """Buffer one event; flush at ``batch_rows``; **block** (back-pressure) if the
        buffer is full because ClickHouse is not keeping up. Never drops."""
        if not self._enabled:
            return
        if not self._started:
            raise RuntimeError("ClickHouseSink.write() before start()")

        self._buffer.append(_ch_row(event))
        if len(self._buffer) >= self._cfg.batch_rows:
            await self._drain_once()
        # if the sink cannot keep up, do not accept more work until it can
        while len(self._buffer) >= self._cfg.max_buffer_rows:
            await self._drain_once()

    async def flush(self) -> None:
        """Deliver every buffered row that can be delivered right now (best effort)."""
        if not self._enabled:
            return
        while self._buffer:
            progressed = await self._drain_once()
            if not progressed:
                return

    # -- introspection --------------------------------------------

    @property
    def pending_rows(self) -> int:
        """Rows buffered in memory, not yet acknowledged by ClickHouse."""
        return len(self._buffer)

    @property
    def is_degraded(self) -> bool:
        """True once ClickHouse has been failing longer than the backpressure threshold."""
        return (
            self._down_since is not None
            and (self._clock() - self._down_since) >= self._cfg.unavailable_backpressure_seconds
        )

    # -- delivery -----------------------------------------------

    async def _drain_once(self) -> bool:
        """Try to deliver one batch. Returns True if rows left the buffer."""
        async with self._flush_lock:
            if not self._buffer:
                return False
            batch = self._buffer[: self._cfg.batch_rows]
            outcome = await self._deliver(batch)
            if outcome:  # delivered, or fatally rejected+spooled
                del self._buffer[: len(batch)]
            return outcome

    async def _deliver(self, rows: list[dict[str, Any]]) -> bool:
        """POST ``rows`` with retry.

        Returns True when handled (delivered or spooled) and False to keep the
        rows buffered for a later retry.
        """
        body = self._insert_head + "\n".join(json.dumps(row, separators=(",", ":")) for row in rows)
        for attempt in range(self._cfg.max_retries + 1):
            try:
                if not self._table_ready:
                    await self._ensure_table()
                await self._post(body)
            except _FatalInsert as exc:
                self._spool_rows(rows)
                _log.error(
                    "ClickHouse rejected a batch (not retried): %s; spooled %d rows", exc, len(rows)
                )
                return True
            except _RetryableInsert as exc:
                self._note_failure(exc)
                if attempt >= self._cfg.max_retries:
                    return False
                await self._sleep(self._backoff(attempt))
            else:
                self._note_success(len(rows))
                return True
        return False

    async def _post(self, body: str) -> None:
        """One HTTP POST to ClickHouse; classify the result as ok / retryable / fatal."""
        assert self._client is not None
        try:
            response = await self._client.post(
                self._base_url, content=body, params=self._params(), headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise _RetryableInsert(f"transport error: {exc}") from exc
        if response.status_code < 300:
            return
        detail = response.text[:300].replace("\n", " ")
        if response.status_code == 429 or response.status_code >= 500:
            raise _RetryableInsert(f"HTTP {response.status_code}: {detail}")
        raise _FatalInsert(f"HTTP {response.status_code}: {detail}")

    async def _ensure_table(self) -> None:
        """Create the ReplacingMergeTree table if it does not exist."""
        assert self._client is not None
        try:
            response = await self._client.post(
                self._base_url,
                content=self._create_table_sql(),
                params={"database": self._cfg.database},
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise _RetryableInsert(f"table DDL transport error: {exc}") from exc
        if response.status_code >= 300:
            raise _RetryableInsert(f"table DDL HTTP {response.status_code}: {response.text[:200]}")
        self._table_ready = True

    # -- helpers ----------------------------------------------

    def _create_table_sql(self) -> str:
        columns = ",\n".join(_column_ddl(name) for name in CORE_COLUMNS)
        json_columns = ",\n".join(f"    `{name}` String" for name in _JSON_COLUMNS)
        # `time` is epoch nanoseconds -> seconds for toDateTime/toYYYYMMDD.
        return (
            f"CREATE TABLE IF NOT EXISTS `{self._cfg.database}`.`{self._cfg.table}` (\n"
            f"{columns},\n{json_columns}\n"
            ") ENGINE = ReplacingMergeTree\n"
            "PARTITION BY toYYYYMMDD(toDateTime(intDiv(time, 1000000000)))\n"
            "ORDER BY (time, source_type, event_uid)"
        )

    def _params(self) -> dict[str, str]:
        params = {"database": self._cfg.database}
        return params

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "text/plain; charset=utf-8"}
        if self._cfg.user:
            headers["X-ClickHouse-User"] = self._cfg.user
        if self._cfg.password:
            headers["X-ClickHouse-Key"] = self._cfg.password
        return headers

    def _backoff(self, attempt: int) -> float:
        return min(self._cfg.backoff_base_seconds * (2**attempt), self._cfg.backoff_max_seconds)

    def _note_failure(self, exc: Exception) -> None:
        if self._down_since is None:
            self._down_since = self._clock()
            _log.warning("ClickHouse insert failing, will retry: %s", exc)

    def _note_success(self, rows: int) -> None:
        if self._down_since is not None:
            _log.info("ClickHouse insert recovered")
        self._down_since = None
        self.rows_delivered += rows
        self.batches_delivered += 1

    async def _timer_loop(self) -> None:
        try:
            while not self._closed:
                await self._sleep(self._cfg.batch_seconds)
                if self._buffer:
                    await self._drain_once()
        except asyncio.CancelledError:
            pass

    # -- spool (never drop) --------------------------------

    def _spool_rows(self, rows: list[dict[str, Any]]) -> None:
        self._spool.mkdir(parents=True, exist_ok=True)
        path = self._spool / f"batch-{uuid.uuid4().hex}.jsonl"
        path.write_text(
            "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
            encoding="utf-8",
        )
        self.rows_spooled += len(rows)

    def _reload_spool(self) -> None:
        if not self._spool.is_dir():
            return
        for path in sorted(self._spool.glob("batch-*.jsonl")):
            rows = [
                json.loads(line) for line in path.read_text("utf-8").splitlines() if line.strip()
            ]
            self._buffer[:0] = rows  # replay before newer events
            path.unlink()
        if self._buffer:
            _log.info("reloaded %d spooled ClickHouse rows for delivery", len(self._buffer))


class _RetryableInsert(RuntimeError):
    """A ClickHouse insert failure worth retrying (transport error, 5xx, 429)."""


class _FatalInsert(RuntimeError):
    """A ClickHouse insert failure not worth retrying (4xx — malformed batch)."""


def _ch_row(event: NormalizedEvent) -> dict[str, Any]:
    """One JSONEachRow object: the 17 core columns + unmapped/enrichments JSON strings."""
    row = core_row(event)
    if row.get("time") is None:
        row["time"] = event.ingest_time_ns  # sorting-key column must be present
    row["source_type"] = event.source_type or "unknown"
    row["unmapped"] = _compact_json(event.ocsf.get("unmapped"))
    row["enrichments"] = _compact_json(event.ocsf.get("enrichments") or event.enrichment)
    return row


def _compact_json(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"), default=str)
