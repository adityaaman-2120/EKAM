"""Tests for :mod:`ulpf.ingest.http_intake` using FastAPI's TestClient."""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from ulpf.config.settings import IngestSettings, Settings
from ulpf.core.errors import IngestError
from ulpf.core.models import RawEvent
from ulpf.ingest.http_intake import create_intake_app


class _Sink:
    """Collects dispatched events; optionally fails after N to simulate backpressure."""

    def __init__(self, fail_after: int | None = None) -> None:
        self.events: list[RawEvent] = []
        self._fail_after = fail_after

    async def __call__(self, event: RawEvent) -> None:
        if self._fail_after is not None and len(self.events) >= self._fail_after:
            raise IngestError("intake queue full")
        self.events.append(event)


def _client(sink: _Sink, *, max_body: int | None = None) -> TestClient:
    ingest = IngestSettings(http_max_body_bytes=max_body) if max_body else IngestSettings()
    settings = Settings(ingest=ingest)
    return TestClient(create_intake_app(settings, sink))


# --------------------------------------------------------------------------
# /ingest/raw


def test_raw_one_event_per_line() -> None:
    sink = _Sink()
    resp = _client(sink).post("/ingest/raw", content=b"line one\nline two\nline three\n")
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] == 3
    assert len(body["event_uids"]) == 3
    assert [e.raw for e in sink.events] == [b"line one", b"line two", b"line three"]
    for event in sink.events:
        assert event.transport == "http"
        assert event.source_id == "http-raw"
    assert sink.events[0].raw_hash == hashlib.sha256(b"line one").hexdigest()


def test_raw_source_id_query_param_and_blank_lines_skipped() -> None:
    sink = _Sink()
    resp = _client(sink).post("/ingest/raw?source_id=cisco_asa", content=b"a\n\n   \nb\n")
    assert resp.json()["accepted"] == 2
    assert {e.source_id for e in sink.events} == {"cisco_asa"}


def test_raw_preserves_non_utf8_bytes() -> None:
    sink = _Sink()
    payload = b"\xff\xfe raw evidence \x00\nsecond \xc3\x28 line"
    _client(sink).post("/ingest/raw", content=payload)
    assert sink.events[0].raw == b"\xff\xfe raw evidence \x00"
    assert sink.events[1].raw == b"second \xc3\x28 line"
    assert sink.events[1].raw_hash == hashlib.sha256(b"second \xc3\x28 line").hexdigest()


# --------------------------------------------------------------------------
# /ingest/json


def test_json_array_reencodes_each_element() -> None:
    sink = _Sink()
    resp = _client(sink).post("/ingest/json", content=b'[{"b":2,"a":1},{"c":3}]')
    assert resp.json()["accepted"] == 2
    assert sink.events[0].raw == b'{"a":1,"b":2}'  # canonical: sorted, compact
    assert sink.events[1].raw == b'{"c":3}'


def test_json_ndjson_keeps_original_line_bytes() -> None:
    sink = _Sink()
    body = b'{"a": 1}\n{"b":  2}\n{"c":3}'
    resp = _client(sink).post("/ingest/json", content=body)
    assert resp.json()["accepted"] == 3
    assert [e.raw for e in sink.events] == [b'{"a": 1}', b'{"b":  2}', b'{"c":3}']


def test_json_invalid_ndjson_line_returns_422() -> None:
    sink = _Sink()
    resp = _client(sink).post("/ingest/json", content=b'{"ok":1}\n{not json}\n')
    assert resp.status_code == 422
    assert sink.events == []


# --------------------------------------------------------------------------
# /ingest/hec


def test_hec_single_string_event() -> None:
    sink = _Sink()
    payload = json.dumps({"event": "hello world", "sourcetype": "syslog"})
    resp = _client(sink).post("/ingest/hec", content=payload)
    assert resp.json()["accepted"] == 1
    assert sink.events[0].raw == b"hello world"
    assert sink.events[0].source_id == "syslog"
    assert sink.events[0].transport == "http"


def test_hec_multiple_concatenated_objects() -> None:
    sink = _Sink()
    payload = '{"event":"a","sourcetype":"s1"}{"event":"b","sourcetype":"s2"}\n{"event":"c"}'
    resp = _client(sink).post("/ingest/hec?source_id=fallback", content=payload)
    assert resp.json()["accepted"] == 3
    assert [e.raw for e in sink.events] == [b"a", b"b", b"c"]
    assert [e.source_id for e in sink.events] == ["s1", "s2", "fallback"]


def test_hec_object_event_is_canonical_json() -> None:
    sink = _Sink()
    payload = json.dumps({"event": {"msg": "x", "n": 1}, "sourcetype": "json"})
    _client(sink).post("/ingest/hec", content=payload)
    assert sink.events[0].raw == b'{"msg":"x","n":1}'


def test_hec_missing_event_field_returns_422() -> None:
    sink = _Sink()
    resp = _client(sink).post("/ingest/hec", content=b'{"sourcetype":"x"}')
    assert resp.status_code == 422
    assert sink.events == []


# --------------------------------------------------------------------------
# cross-cutting


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/ingest/raw", b"x\ny"),
        ("/ingest/json", b'[{"a":1}]'),
        ("/ingest/hec", b'{"event":"e"}'),
    ],
)
def test_response_shape(path: str, body: bytes) -> None:
    resp = _client(_Sink()).post(path, content=body)
    assert resp.status_code == 200
    assert set(resp.json()) == {"accepted", "event_uids"}


def test_body_over_max_size_returns_413() -> None:
    sink = _Sink()
    client = _client(sink, max_body=32)
    resp = client.post("/ingest/raw", content=b"x" * 64)
    assert resp.status_code == 413
    assert sink.events == []
    # under the limit still works
    ok = client.post("/ingest/raw", content=b"short line")
    assert ok.status_code == 200


def test_backpressure_from_on_event_maps_to_503() -> None:
    sink = _Sink(fail_after=1)
    resp = _client(sink).post("/ingest/raw", content=b"first\nsecond\nthird")
    assert resp.status_code == 503
    assert resp.json()["detail"]["accepted"] == 1
