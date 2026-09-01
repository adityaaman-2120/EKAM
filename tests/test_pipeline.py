"""Tests for :mod:`ulpf.core.pipeline`."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.errors import PipelineStoppedError
from ulpf.core.metrics import snapshot
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import NoOpStage, Pipeline, RawStoreStage
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.raw_store import RawStore


def _settings(tmp_path: Path, workers: int = 2) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        pipeline=PipelineSettings(worker_count=workers),
        ingest=IngestSettings(queue_max_size=1000),
    )


def _raw(i: int, marker: bytes = b"") -> RawEvent:
    return make_raw_event(f"event-{i} ".encode() + marker, source_id="test", transport="http")


class _RecordingStage:
    name = "record"

    def __init__(self) -> None:
        self.seen: list[RawEvent] = []

    async def process(self, event: RawEvent) -> RawEvent:
        self.seen.append(event)
        return event


class _FlakyStage:
    """Raises for events whose raw contains b'bad'; passes the rest through."""

    name = "flaky"

    def __init__(self) -> None:
        self.calls = 0

    async def process(self, event: RawEvent) -> RawEvent:
        self.calls += 1
        if b"bad" in event.raw:
            raise ValueError("bad event")
        return event


class _DropStage:
    name = "drop"

    async def process(self, event: RawEvent) -> None:
        return None


class _SlowStage:
    name = "slow"

    async def process(self, event: RawEvent) -> RawEvent:
        await asyncio.sleep(0.03)
        return event


async def test_events_flow_through_stages_in_order(tmp_path: Path) -> None:
    a, b = _RecordingStage(), _RecordingStage()
    b.name = "record2"
    pipeline = Pipeline(_settings(tmp_path), [a, b])

    key = 'ulpf_stage_latency_seconds_count{stage="record"}'
    before = snapshot().get(key, 0.0)

    pipeline.start()
    events = [_raw(i) for i in range(3)]
    for event in events:
        await pipeline.submit(event)
    await pipeline.queue.join()

    assert [e.event_uid for e in a.seen] == [e.event_uid for e in events]
    assert [e.event_uid for e in b.seen] == [e.event_uid for e in events]
    assert snapshot()[key] - before == 3.0

    await pipeline.stop()


async def test_stage_exception_dead_letters_and_worker_survives(tmp_path: Path) -> None:
    flaky = _FlakyStage()
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path, workers=1), [flaky, downstream])

    pipeline.start()
    markers = [b"", b"bad", b"", b"bad", b""]
    for i, marker in enumerate(markers):
        await pipeline.submit(_raw(i, marker))
    await pipeline.queue.join()

    # 3 good events reached the downstream stage; the worker kept going past
    # each exception (the good events after the bad ones were still processed).
    assert len(downstream.seen) == 3
    assert flaky.calls == 5

    stats = pipeline.dlq.stats()
    assert stats["total"] == 2
    assert stats["by_stage"] == {"flaky": 2}
    assert stats["by_reason"] == {"ValueError": 2}
    dead = list(pipeline.dlq.iter_recent(10))
    assert all(b"bad" in d.raw for d in dead)

    await pipeline.stop()


async def test_none_return_stops_processing_without_dlq(tmp_path: Path) -> None:
    drop = _DropStage()
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path), [drop, downstream])

    pipeline.start()
    for i in range(4):
        await pipeline.submit(_raw(i))
    await pipeline.queue.join()

    assert downstream.seen == []
    assert pipeline.dlq.stats()["total"] == 0

    await pipeline.stop()


async def test_shutdown_flushes_pending_raw_store_writes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    # Large thresholds: nothing auto-flushes, so only stop() can persist.
    store = RawStore(settings, max_buffered_records=10_000, max_buffer_seconds=10_000)
    pipeline = Pipeline(settings, [RawStoreStage(store), NoOpStage()])

    pipeline.start()
    for i in range(5):
        await pipeline.submit(_raw(i))
    await pipeline.queue.join()

    # Written into the buffer, but not yet on disk.
    assert list((tmp_path / "bronze").rglob("events.ndjson.gz")) == []

    await pipeline.stop()

    on_disk = list(store.iter_all())
    assert len(on_disk) == 5


async def test_submit_after_stop_raises(tmp_path: Path) -> None:
    pipeline = Pipeline(_settings(tmp_path), [NoOpStage()])
    pipeline.start()
    await pipeline.stop()
    with pytest.raises(PipelineStoppedError):
        await pipeline.submit(_raw(0))


async def test_double_start_raises(tmp_path: Path) -> None:
    pipeline = Pipeline(_settings(tmp_path), [NoOpStage()])
    pipeline.start()
    try:
        with pytest.raises(RuntimeError):
            pipeline.start()
    finally:
        await pipeline.stop()


async def test_stop_drains_inflight_events(tmp_path: Path) -> None:
    downstream = _RecordingStage()
    pipeline = Pipeline(_settings(tmp_path, workers=3), [_SlowStage(), downstream])

    pipeline.start()
    for i in range(12):
        await pipeline.submit(_raw(i))
    await pipeline.stop()  # must wait for all 12 to finish, not drop them

    assert len(downstream.seen) == 12
