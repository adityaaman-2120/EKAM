"""Tests for :mod:`ulpf.sinks.splunk_hec_sink`, driven by a mocked HEC endpoint."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from ulpf.config.settings import Settings, SplunkHecSettings
from ulpf.core.models import NormalizedEvent
from ulpf.normalize.crosswalk.cim import to_cim
from ulpf.sinks.splunk_hec_sink import SplunkHecSink

_BASE_NS = 1_788_264_000_000_000_000  # 2026-09-01T12:00:00Z


class RecordingSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)
        await asyncio.sleep(0)


class FakeHec:
    """A mock Splunk HEC endpoint: records requests, scriptable responses."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, dict[str, str]]] = []  # (url, body, headers)
        self.unreachable = False
        self.health_status = 200
        self.event_default = 200
        self.event_responses: list[int] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectError("connection refused", request=request)
        url = str(request.url)
        body = request.content.decode() if request.content else ""
        self.requests.append((url, body, dict(request.headers)))

        if url.endswith("collector/health"):
            if self.health_status == 200:
                return httpx.Response(200, json={"text": "HEC is healthy", "code": 17})
            return httpx.Response(self.health_status, text="unhealthy")
        if url.endswith("collector/event"):
            status = self.event_responses.pop(0) if self.event_responses else self.event_default
            if status < 300:
                return httpx.Response(status, json={"text": "Success", "code": 0})
            return httpx.Response(status, text="hec error")
        return httpx.Response(404, text="not found")

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._handle))

    @property
    def event_requests(self) -> list[str]:
        return [b for u, b, _h in self.requests if u.endswith("collector/event")]

    def events(self, index: int = 0) -> list[dict[str, Any]]:
        return [
            json.loads(line) for line in self.event_requests[index].splitlines() if line.strip()
        ]


def _settings(tmp_path: Path, **hec: Any) -> Settings:
    hec.setdefault("enabled", True)
    hec.setdefault("token", "s3cr3t-token")
    return Settings(splunk_hec=SplunkHecSettings(**hec))


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
    fake = FakeHec()
    fake.unreachable = True
    sink = SplunkHecSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())

    with caplog.at_level(logging.WARNING, logger="ulpf.sinks.splunk_hec_sink"):
        await sink.start(timer=False)
    assert any("DISABLED" in r.message for r in caplog.records)

    await sink.write(_ne("a"))  # silent no-op
    assert sink.pending_events == 0
    await sink.close()
    assert fake.event_requests == []


async def test_unhealthy_status_also_disables_the_sink(tmp_path: Path) -> None:
    fake = FakeHec()
    fake.health_status = 503
    sink = SplunkHecSink(_settings(tmp_path), client=fake.client(), sleep=RecordingSleep())
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert sink.pending_events == 0
    await sink.close()


async def test_disabled_by_config_makes_no_http_calls(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(_settings(tmp_path, enabled=False), client=fake.client())
    await sink.start()
    await sink.write(_ne("a"))
    await sink.flush()
    await sink.close()
    assert fake.requests == []


async def test_health_check_and_posts_use_token_auth(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1, token="my-token"),
        client=fake.client(),
        sleep=RecordingSleep(),
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    await sink.close()
    assert all(h["authorization"] == "Splunk my-token" for _u, _b, h in fake.requests)


# --------------------------------------------------------------------------
# CIM crosswalk + sourcetype-per-source


async def test_posts_the_cim_crosswalk_with_sourcetype_per_source(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=2, source="ulpf-test", host="collector-1"),
        client=fake.client(),
        sleep=RecordingSleep(),
    )
    await sink.start(timer=False)

    forti = _ne("evt-1", source="fortigate_traffic")
    suri = _ne("evt-2", source="suricata_eve_alert", offset=1)
    await sink.write(forti)
    await sink.write(suri)

    assert len(fake.event_requests) == 1
    events = fake.events()
    assert len(events) == 2
    assert events[0]["sourcetype"] == "fortigate_traffic"
    assert events[1]["sourcetype"] == "suricata_eve_alert"
    assert events[0]["source"] == "ulpf-test" and events[0]["host"] == "collector-1"
    assert events[0]["event"] == to_cim(forti.ocsf)
    assert "tags" in events[0]["event"]
    assert "class_uid" not in events[0]["event"]  # CIM, not raw OCSF
    await sink.close()


async def test_time_field_is_epoch_seconds(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    event = fake.events()[0]
    assert event["time"] == pytest.approx(_BASE_NS / 1_000_000_000)
    await sink.close()


async def test_index_field_only_present_when_configured(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert "index" not in fake.events()[0]
    await sink.close()

    fake2 = FakeHec()
    sink2 = SplunkHecSink(
        _settings(tmp_path, batch_events=1, index="ulpf_main"),
        client=fake2.client(),
        sleep=RecordingSleep(),
    )
    await sink2.start(timer=False)
    await sink2.write(_ne("b"))
    assert fake2.events()[0]["index"] == "ulpf_main"
    await sink2.close()


async def test_timer_flushes_a_partial_batch(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1000, batch_seconds=0.01), client=fake.client()
    )
    await sink.start()
    try:
        await sink.write(_ne("a"))
        for _ in range(50):
            if fake.event_requests:
                break
            await asyncio.sleep(0.01)
        assert len(fake.event_requests) == 1
    finally:
        await sink.close()


# --------------------------------------------------------------------------
# retry / drop (never blocks)


async def test_retries_a_failed_batch_then_succeeds(tmp_path: Path) -> None:
    fake = FakeHec()
    fake.event_responses = [503]
    sleep = RecordingSleep()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1, backoff_base_seconds=0.2),
        client=fake.client(),
        sleep=sleep,
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert len(fake.event_requests) == 2 and sleep.calls == [0.2]
    assert sink.events_delivered == 1
    await sink.close()


async def test_persistent_failure_is_dropped_and_never_blocks(tmp_path: Path) -> None:
    fake = FakeHec()
    fake.event_default = 503
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=2, max_retries=1),
        client=fake.client(),
        sleep=RecordingSleep(),
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    await sink.write(_ne("b"))  # triggers the flush -> keeps failing

    assert sink.pending_events == 0  # dropped, not stuck
    assert sink.events_dropped == 2 and sink.batches_dropped == 1 and sink.events_delivered == 0
    await sink.close()


async def test_fatal_4xx_is_dropped_without_retrying(tmp_path: Path) -> None:
    fake = FakeHec()
    fake.event_default = 403  # e.g. invalid token
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert len(fake.event_requests) == 1  # a single attempt, no retry
    assert sink.events_dropped == 1
    await sink.close()


async def test_close_flushes_pending_events_and_is_idempotent(tmp_path: Path) -> None:
    fake = FakeHec()
    sink = SplunkHecSink(
        _settings(tmp_path, batch_events=1000), client=fake.client(), sleep=RecordingSleep()
    )
    await sink.start(timer=False)
    await sink.write(_ne("a"))
    assert fake.event_requests == []
    await sink.close()
    assert len(fake.event_requests) == 1
    await sink.close()  # no error, no extra request
    assert len(fake.event_requests) == 1
