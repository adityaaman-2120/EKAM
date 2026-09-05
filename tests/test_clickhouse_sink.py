"""Tests for :mod:`ulpf.sinks.clickhouse_sink`.

Behaviour tests drive a mocked ClickHouse HTTP endpoint (``httpx.MockTransport``).
An optional integration test runs against a real server when ``CLICKHOUSE_URL``
is set and reachable; it is skipped cleanly otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

from ulpf.config.settings import ClickHouseSettings, Settings, StorageSettings
from ulpf.core.models import NormalizedEvent
from ulpf.sinks.clickhouse_sink import ClickHouseSink
from ulpf.sinks.parquet_sink import CORE_COLUMNS

_BASE_NS = 1_788_264_000_000_000_000


class FakeClickHouse:
    """A mock ClickHouse HTTP server: records requests, scriptable responses."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []  # (url, body)
        self.ddl_status = 200
        self.insert_default = 200
        self.insert_responses: list[int] = []  # consumed one per INSERT, then default

    def _handle(self, request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        self.requests.append((str(request.url), body))
        if body.lstrip().startswith("CREATE TABLE"):
            return httpx.Response(self.ddl_status, text="" if self.ddl_status < 300 else "ddl err")
        status = self.insert_responses.pop(0) if self.insert_responses else self.insert_default
        return httpx.Response(status, text="" if status < 300 else f"insert err {status}")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    @property
    def ddls(self) -> list[str]:
        return [b for _, b in self.requests if b.lstrip().startswith("CREATE TABLE")]

    @property
    def inserts(self) -> list[str]:
        return [b for _, b in self.requests if b.startswith("INSERT INTO")]

    def insert_rows(self, index: int = 0) -> list[dict[str, Any]]:
        body = self.inserts[index]
        payload = body.split("FORMAT JSONEachRow\n", 1)[1]
        return [json.loads(line) for line in payload.splitlines() if line.strip()]


class RecordingSleep:
    """Records the requested delays but yields control instead of really sleeping."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)
        await asyncio.sleep(0)  # cooperate with the event loop, but do not wait


def _settings(tmp_path: Path, **clickhouse: Any) -> Settings:
    clickhouse.setdefault("enabled", True)
    return Settings(
        storage=StorageSettings(state_path=tmp_path / "state"),
        clickhouse=ClickHouseSettings(**clickhouse),
    )


def _ne(uid: str, source: str = "fortigate_traffic", offset: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        event_uid=uid,
        raw_hash="h" * 64,
        ingest_time_ns=_BASE_NS + offset,
        ocsf={
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": 6,
            "type_uid": 400106,
            "severity_id": 1,
            "time": _BASE_NS + offset,
            "src_endpoint": {"ip": "192.0.2.10", "port": 51000},
            "dst_endpoint": {"ip": "198.51.100.5", "port": 443},
            "connection_info": {"protocol_name": "tcp"},
            "traffic": {"bytes_in": 100, "bytes_out": 200},
            "action_id": 1,
            "unmapped": {"transip": "203.0.113.9"},
            "enrichments": {"network_context": {"direction": "outbound"}},
        },
        source_type=source,
        mapping_version="1.0.0",
        enrichment={},
    )


def _spool_files(tmp_path: Path) -> list[Path]:
    return list((tmp_path / "state" / "clickhouse_spool").glob("batch-*.jsonl"))


# --------------------------------------------------------------------------
# table creation


async def test_creates_replacing_merge_tree_table_on_start(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    sink = ClickHouseSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.close()

    assert len(fake.ddls) == 1
    ddl = fake.ddls[0]
    assert "CREATE TABLE IF NOT EXISTS" in ddl
    assert "ENGINE = ReplacingMergeTree" in ddl
    assert "ORDER BY (time, source_type, event_uid)" in ddl
    assert "PARTITION BY toYYYYMMDD(toDateTime(intDiv(time, 1000000000)))" in ddl
    assert "`time` Int64" in ddl and "`src_port` Nullable(Int64)" in ddl
    assert "`unmapped` String" in ddl and "`enrichments` String" in ddl


# --------------------------------------------------------------------------
# batching + row shape


async def test_flushes_at_batch_rows_with_the_expected_columns(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=3), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)

    for i in range(3):
        await sink.write(_ne(f"e{i}", offset=i))
    assert len(fake.inserts) == 1 and sink.pending_rows == 0

    rows = fake.insert_rows()
    assert len(rows) == 3
    assert set(rows[0]) == set(CORE_COLUMNS) | {"unmapped", "enrichments"}
    assert isinstance(rows[0]["time"], int) and rows[0]["source_type"] == "fortigate_traffic"
    assert json.loads(rows[0]["unmapped"]) == {"transip": "203.0.113.9"}
    assert json.loads(rows[0]["enrichments"]) == {"network_context": {"direction": "outbound"}}

    await sink.write(_ne("e3"))
    assert len(fake.inserts) == 1 and sink.pending_rows == 1  # buffered, not yet flushed
    await sink.close()
    assert len(fake.inserts) == 2 and sink.rows_delivered == 4


async def test_timer_flushes_a_partial_batch(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=1000, batch_seconds=0.01), client=fake.client()
    )
    await sink.start()  # real timer
    try:
        await sink.write(_ne("a"))
        await sink.write(_ne("b"))
        for _ in range(50):
            if fake.inserts:
                break
            await _tick()
        assert len(fake.inserts) == 1 and len(fake.insert_rows()) == 2
    finally:
        await sink.close()


async def _tick() -> None:
    await asyncio.sleep(0.01)


# --------------------------------------------------------------------------
# retry + backoff


async def test_retries_with_exponential_backoff_then_succeeds(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    fake.insert_responses = [503, 503, 200]
    sleep = RecordingSleep()
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=2, backoff_base_seconds=0.5, max_retries=5),
        client=fake.client(),
        sleep=sleep,
    )
    await sink.start(timer=False)

    await sink.write(_ne("a"))
    await sink.write(_ne("b"))  # hits batch_rows -> one drain that retries

    assert len(fake.inserts) == 3  # 503, 503, 200
    assert sleep.calls == [0.5, 1.0]  # base, base*2
    assert sink.pending_rows == 0 and sink.rows_delivered == 2 and sink.batches_delivered == 1
    await sink.close()


# --------------------------------------------------------------------------
# backpressure — never drop


async def test_backpressure_when_clickhouse_is_down_and_never_drops(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    fake.insert_default = 503
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=2, max_buffer_rows=6, max_retries=1),
        client=fake.client(),
        sleep=RecordingSleep(),
    )
    await sink.start(timer=False)

    for i in range(5):
        await sink.write(_ne(f"e{i}", offset=i))  # each returns; nothing delivered
    assert sink.pending_rows == 5 and sink.rows_delivered == 0

    blocked = asyncio.create_task(sink.write(_ne("blocked")))
    await asyncio.sleep(0.05)
    assert not blocked.done()  # buffer full + CH down -> the writer is back-pressured
    assert sink.pending_rows == 6  # the 6th row is buffered, not dropped

    fake.insert_default = 200  # ClickHouse recovers
    await asyncio.wait_for(blocked, timeout=1.0)  # the blocked write now completes
    await sink.flush()
    assert sink.pending_rows == 0 and sink.rows_delivered == 6  # every event delivered
    await sink.close()


# --------------------------------------------------------------------------
# fatal 4xx -> spool, not retry, not drop


async def test_non_retryable_4xx_batch_is_spooled_not_retried(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    fake.insert_default = 400
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=2), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)

    await sink.write(_ne("a"))
    await sink.write(_ne("b"))

    assert len(fake.inserts) == 1  # one POST, no retry
    assert sink.pending_rows == 0
    files = _spool_files(tmp_path)
    assert len(files) == 1
    assert len(files[0].read_text("utf-8").splitlines()) == 2
    assert sink.rows_spooled == 2
    await sink.close()


# --------------------------------------------------------------------------
# shutdown spool + reload


async def test_shutdown_spools_undelivered_rows_and_start_reloads_them(tmp_path: Path) -> None:
    down = FakeClickHouse()
    down.insert_default = 503
    sink = ClickHouseSink(
        _settings(tmp_path, batch_rows=100, max_retries=1),
        client=down.client(),
        sleep=RecordingSleep(),
    )
    await sink.start(timer=False)
    for i in range(3):
        await sink.write(_ne(f"e{i}", offset=i))
    await sink.close()

    files = _spool_files(tmp_path)
    assert len(files) == 1 and len(files[0].read_text("utf-8").splitlines()) == 3

    up = FakeClickHouse()
    sink2 = ClickHouseSink(
        _settings(tmp_path, batch_rows=100), client=up.client(), sleep=RecordingSleep()
    )
    await sink2.start(timer=False)
    assert sink2.pending_rows == 3  # reloaded from the spool
    assert _spool_files(tmp_path) == []  # spool consumed

    await sink2.flush()
    assert len(up.inserts) == 1 and len(up.insert_rows()) == 3 and sink2.pending_rows == 0
    await sink2.close()


# --------------------------------------------------------------------------
# guards


async def test_disabled_sink_makes_no_http_calls(tmp_path: Path) -> None:
    fake = FakeClickHouse()
    sink = ClickHouseSink(_settings(tmp_path, enabled=False), client=fake.client())
    await sink.start()
    await sink.write(_ne("a"))
    await sink.flush()
    await sink.close()
    assert fake.requests == [] and sink.pending_rows == 0


async def test_write_before_start_raises(tmp_path: Path) -> None:
    sink = ClickHouseSink(_settings(tmp_path), client=FakeClickHouse().client())
    with pytest.raises(RuntimeError):
        await sink.write(_ne("a"))


# --------------------------------------------------------------------------
# optional integration test


def _clickhouse_reachable() -> bool:
    url = os.environ.get("CLICKHOUSE_URL")
    if not url:
        return False
    try:
        return httpx.get(url.rstrip("/") + "/ping", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not _clickhouse_reachable(), reason="no ClickHouse (set CLICKHOUSE_URL)")
async def test_integration_at_least_once_duplicates_collapse(tmp_path: Path) -> None:
    url = os.environ["CLICKHOUSE_URL"]
    table = f"ulpf_it_{uuid.uuid4().hex[:12]}"
    settings = _settings(tmp_path, url=url, table=table, batch_rows=5, database="default")
    sink = ClickHouseSink(settings)
    await sink.start(timer=False)
    try:
        events = [_ne(f"it-{i}", offset=i) for i in range(10)]
        for event in events:
            await sink.write(event)
        await sink.write(events[0])  # at-least-once duplicate
        await sink.flush()
    finally:
        await sink.close()

    async with httpx.AsyncClient() as client:

        async def scalar(sql: str) -> int:
            resp = await client.post(url, params={"query": sql})
            resp.raise_for_status()
            return int(resp.text.strip())

        total = await scalar(f"SELECT count() FROM default.`{table}` FINAL")
        distinct = await scalar(f"SELECT uniqExact(event_uid) FROM default.`{table}`")
        await client.post(url, params={"query": f"DROP TABLE IF EXISTS default.`{table}`"})

    assert distinct == 10  # 11 rows inserted, 10 distinct events
    assert total == 10  # ReplacingMergeTree FINAL collapses the duplicate
