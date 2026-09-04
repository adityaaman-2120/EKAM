"""Tests for :mod:`ulpf.sinks.opensearch_sink`, driven by a mocked HTTP endpoint."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from ulpf.config.settings import OpenSearchSettings, Settings
from ulpf.core.models import NormalizedEvent
from ulpf.normalize.crosswalk.ecs import to_ecs
from ulpf.sinks.opensearch_sink import OpenSearchSink

_BASE_NS = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z


class RecordingSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)
        await asyncio.sleep(0)


class FakeOpenSearch:
    """A mock OpenSearch HTTP endpoint: records requests, scriptable responses."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, str]] = []  # (method, url, body)
        self.unreachable = False
        self.health_status = 200
        self.template_status = 200
        self.bulk_default = 200
        self.bulk_responses: list[tuple[int, dict[str, Any] | None]] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("connection refused", request=request)
        url = str(request.url)
        body = request.content.decode() if request.content else ""
        self.requests.append((request.method, url, body))

        if request.method == "GET":  # the sink only ever issues the health-check GET
            return httpx.Response(self.health_status, json={"cluster_name": "test"})
        if "_index_template" in url:
            return httpx.Response(self.template_status, json={"acknowledged": True})
        if url.endswith("_bulk"):
            status, payload = (
                self.bulk_responses.pop(0) if self.bulk_responses else (self.bulk_default, None)
            )
            if payload is None:
                payload = {"errors": False, "items": []} if status < 300 else None
            if status < 300:
                return httpx.Response(status, json=payload)
            return httpx.Response(status, text="bulk error")
        return httpx.Response(404, text="not found")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    @property
    def bulk_requests(self) -> list[str]:
        return [b for _, u, b in self.requests if u.endswith("_bulk")]

    @property
    def template_requests(self) -> list[tuple[str, str]]:
        return [(u, b) for _, u, b in self.requests if "_index_template" in u]

    def bulk_lines(self, index: int = 0) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.bulk_requests[index].splitlines() if line.strip()]


def _settings(tmp_path: Path, **opensearch: Any) -> Settings:
    opensearch.setdefault("enabled", True)
    return Settings(opensearch=OpenSearchSettings(**opensearch))


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
            "action": "Allowed",
            "action_id": 1,
            "firewall_rule": {"name": "allow-web"},
            "metadata": {"product": {"vendor_name": "Fortinet", "name": "FortiGate"}},
        },
        source_type=source,
        mapping_version="1.0.0",
        enrichment={},
    )


# --------------------------------------------------------------------------
# fail-soft startup


async def test_disables_itself_when_unreachable_at_startup(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeOpenSearch()
    fake.unreachable = True
    sink = OpenSearchSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())

    with caplog.at_level(logging.WARNING, logger="ulpf.sinks.opensearch_sink"):
        await sink.start(timer=False)
    assert any("DISABLED" in r.message for r in caplog.records)

    await sink.write(_ne("a"))  # silent no-op, never raises
    assert sink.pending_docs == 0
    await sink.close()
    assert fake.bulk_requests == []


async def test_unhealthy_status_also_disables_the_sink(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    fake.health_status = 503
    sink = OpenSearchSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert sink.pending_docs == 0
    await sink.close()


async def test_disabled_by_config_makes_no_http_calls(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path, enabled=False), client=fake.client())
    await sink.start()
    await sink.write(_ne("a"))
    await sink.flush()
    await sink.close()
    assert fake.requests == []


# --------------------------------------------------------------------------
# index template


async def test_creates_the_index_template_with_ecs_field_types(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.close()

    assert len(fake.template_requests) == 1
    url, body = fake.template_requests[0]
    assert "ulpf-ecs-template" in url
    template = json.loads(body)
    assert template["index_patterns"] == ["ulpf-ecs-*"]
    props = template["template"]["mappings"]["properties"]
    assert props["source"]["properties"]["ip"] == {"type": "ip"}
    assert props["destination"]["properties"]["port"] == {"type": "long"}
    assert props["related"]["properties"]["ip"] == {"type": "ip"}
    assert props["event"]["properties"]["severity"] == {"type": "long"}


async def test_template_failure_does_not_disable_the_sink(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    fake.template_status = 500
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=1), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert len(fake.bulk_requests) == 1  # still indexes despite the template failure
    await sink.close()


# --------------------------------------------------------------------------
# bulk indexing shape


async def test_bulk_body_indexes_the_ecs_crosswalk_not_raw_ocsf(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=2), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)

    event = _ne("evt-1")
    await sink.write(event)
    await sink.write(_ne("evt-2", offset=1))

    assert len(fake.bulk_requests) == 1
    lines = fake.bulk_lines()
    assert len(lines) == 4  # 2 action + 2 doc lines
    action, doc = lines[0], lines[1]
    assert action == {"index": {"_index": "ulpf-ecs-2026.09.01", "_id": "evt-1"}}
    assert doc == to_ecs(event.ocsf)
    assert "class_uid" not in doc and "severity_id" not in doc  # ECS, not raw OCSF
    await sink.close()


async def test_index_name_is_derived_from_the_ecs_timestamp(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=1), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    action = fake.bulk_lines()[0]
    assert action["index"]["_index"] == "ulpf-ecs-2026.09.01"
    await sink.close()


async def test_timer_flushes_a_partial_batch(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=1000, batch_seconds=0.01), client=fake.client())
    await sink.start()
    try:
        await sink.write(_ne("a"))
        for _ in range(50):
            if fake.bulk_requests:
                break
            await asyncio.sleep(0.01)
        assert len(fake.bulk_requests) == 1
    finally:
        await sink.close()


# --------------------------------------------------------------------------
# retry / drop (never blocks)


async def test_retries_a_failed_batch_then_succeeds(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    fake.bulk_responses = [(503, None)]
    sleep = RecordingSleep()
    sink = OpenSearchSink(
        _settings(tmp_path, batch_docs=1, backoff_base_seconds=0.2), client=fake.client(), sleep=sleep
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert len(fake.bulk_requests) == 2 and sleep.calls == [0.2]
    assert sink.docs_indexed == 1
    await sink.close()


async def test_persistent_failure_is_dropped_and_never_blocks(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    fake.bulk_default = 503
    sink = OpenSearchSink(
        _settings(tmp_path, batch_docs=2, max_retries=1), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    await sink.write(_ne("b"))  # triggers the batch flush -> keeps failing

    assert sink.pending_docs == 0  # dropped, not stuck retrying forever
    assert sink.docs_dropped == 2 and sink.batches_dropped == 1 and sink.docs_indexed == 0
    await sink.close()


async def test_fatal_4xx_is_dropped_without_retrying(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    fake.bulk_default = 400
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=1), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert len(fake.bulk_requests) == 1  # a single attempt, no retry
    assert sink.docs_dropped == 1
    await sink.close()


async def test_partial_item_errors_are_logged_but_the_batch_is_not_retried(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeOpenSearch()
    fake.bulk_responses = [
        (
            200,
            {
                "errors": True,
                "items": [
                    {"index": {"status": 400, "error": {"type": "mapper_parsing_exception"}}},
                    {"index": {"status": 201}},
                ],
            },
        )
    ]
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=2), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    with caplog.at_level(logging.WARNING, logger="ulpf.sinks.opensearch_sink"):
        await sink.write(_ne("a"))
        await sink.write(_ne("b", offset=1))
    assert len(fake.bulk_requests) == 1  # the HTTP request itself succeeded -> no retry
    assert any("rejected" in r.message for r in caplog.records)
    await sink.close()


async def test_close_flushes_pending_docs_and_is_idempotent(tmp_path: Path) -> None:
    fake = FakeOpenSearch()
    sink = OpenSearchSink(_settings(tmp_path, batch_docs=1000), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert fake.bulk_requests == []
    await sink.close()
    assert len(fake.bulk_requests) == 1
    await sink.close()  # no error, no extra request
    assert len(fake.bulk_requests) == 1
