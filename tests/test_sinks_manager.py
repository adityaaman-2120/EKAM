"""Tests for :mod:`ulpf.sinks.manager` — the fan-out final pipeline stage."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.models import NormalizedEvent
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.manager import SinkHandle, SinkManager
from ulpf.sinks.parquet_sink import ParquetSink

_BASE_NS = 1_788_264_000_000_000_000


class FakeAsyncSink:
    """A minimal async sink: records calls, can fail on demand."""

    def __init__(
        self,
        *,
        fail_write: bool = False,
        fail_start: bool = False,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.started = False
        self.closed = False
        self.writes: list[NormalizedEvent] = []
        self.fail_write = fail_write
        self.fail_start = fail_start
        self.error = error or RuntimeError("boom")
        self.delay = delay

    async def start(self) -> None:
        if self.fail_start:
            raise RuntimeError("start failed")
        self.started = True

    async def write(self, event: NormalizedEvent) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        self.writes.append(event)
        if self.fail_write:
            raise self.error

    async def close(self) -> None:
        self.closed = True


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            state_path=tmp_path / "state",
        )
    )


def _ne(uid: str = "e1", source: str = "fortigate_traffic") -> NormalizedEvent:
    return NormalizedEvent(
        event_uid=uid,
        raw_hash="a" * 64,
        ingest_time_ns=_BASE_NS,
        ocsf={"class_uid": 4001, "category_uid": 4, "time": _BASE_NS},
        source_type=source,
        mapping_version="1.0.0",
        enrichment={},
    )


def _manager(tmp_path: Path, **handles: tuple[FakeAsyncSink, bool]) -> SinkManager:
    """Build a manager with fake sinks: kwarg name -> (fake_sink, required)."""
    manager = SinkManager(_settings(tmp_path))
    for name, (fake, required) in handles.items():
        manager.register(SinkHandle.for_async_sink(name, fake, required=required))
    return manager


# --------------------------------------------------------------------------
# from_settings wiring


def test_from_settings_registers_parquet_required_and_others_optional(tmp_path: Path) -> None:
    manager = SinkManager.from_settings(_settings(tmp_path))
    assert manager.sink_names == ["parquet", "clickhouse", "opensearch", "splunk_hec"]
    assert manager.required_sink_names == ["parquet"]
    assert manager.name == "sinks"


# --------------------------------------------------------------------------
# fan-out is concurrent


async def test_writes_are_fanned_out_concurrently_not_sequentially(tmp_path: Path) -> None:
    slow_sinks = {f"s{i}": (FakeAsyncSink(delay=0.08), False) for i in range(4)}
    manager = _manager(tmp_path, **slow_sinks)

    start = time.perf_counter()
    result = await manager.process(_ne())
    elapsed = time.perf_counter() - start

    assert result is not None
    assert elapsed < 0.08 * 2  # concurrent: ~0.08s, not ~0.32s if sequential


# --------------------------------------------------------------------------
# success path


async def test_all_sinks_succeeding_returns_the_event_untouched(tmp_path: Path) -> None:
    required = FakeAsyncSink()
    optional = FakeAsyncSink()
    manager = _manager(tmp_path, required=(required, True), optional=(optional, False))
    event = _ne()

    before = snapshot()
    result = await manager.process(event)

    assert result is event
    assert required.writes == [event] and optional.writes == [event]
    assert DeadLetterQueue(_settings(tmp_path)).stats()["total"] == 0

    after = snapshot()
    assert (
        after.get('ulpf_sink_writes_total{sink="required",status="ok"}', 0)
        - before.get('ulpf_sink_writes_total{sink="required",status="ok"}', 0)
        == 1.0
    )
    assert (
        after.get('ulpf_sink_writes_total{sink="optional",status="ok"}', 0)
        - before.get('ulpf_sink_writes_total{sink="optional",status="ok"}', 0)
        == 1.0
    )
    assert (
        after['ulpf_sink_latency_seconds_count{sink="required"}']
        - before.get('ulpf_sink_latency_seconds_count{sink="required"}', 0)
        == 1.0
    )


async def test_no_registered_sinks_is_a_passthrough(tmp_path: Path) -> None:
    manager = SinkManager(_settings(tmp_path))
    event = _ne()
    assert await manager.process(event) is event
    assert DeadLetterQueue(_settings(tmp_path)).stats()["total"] == 0


# --------------------------------------------------------------------------
# required-sink failure -> DLQ


async def test_required_sink_failure_dead_letters_the_event(tmp_path: Path) -> None:
    required = FakeAsyncSink(fail_write=True, error=RuntimeError("disk full"))
    optional = FakeAsyncSink()
    manager = _manager(tmp_path, req=(required, True), opt=(optional, False))
    event = _ne(uid="dead-1")

    result = await manager.process(event)

    assert result is None  # dropped from the pipeline
    assert optional.writes == [event]  # the optional sink still got the write

    dlq = DeadLetterQueue(_settings(tmp_path))
    assert dlq.stats()["total"] == 1
    (entry,) = list(dlq.iter_recent(1))
    assert entry.event_uid == "dead-1" and entry.raw_hash == event.raw_hash
    assert entry.stage == "sinks" and entry.reason == "required_sink_failed"
    assert entry.detail["failed_sinks"] == ["req"]
    assert "disk full" in entry.detail["errors"]["req"]
    assert entry.detail["source_type"] == "fortigate_traffic"


async def test_multiple_required_failures_are_all_listed_in_one_dlq_entry(tmp_path: Path) -> None:
    a = FakeAsyncSink(fail_write=True, error=RuntimeError("a broke"))
    b = FakeAsyncSink(fail_write=True, error=RuntimeError("b broke"))
    manager = _manager(tmp_path, a=(a, True), b=(b, True))

    result = await manager.process(_ne())

    assert result is None
    dlq = DeadLetterQueue(_settings(tmp_path))
    assert dlq.stats()["total"] == 1
    (entry,) = list(dlq.iter_recent(1))
    assert set(entry.detail["failed_sinks"]) == {"a", "b"}
    assert "a broke" in entry.detail["errors"]["a"]
    assert "b broke" in entry.detail["errors"]["b"]


async def test_optional_sink_failure_does_not_dead_letter(tmp_path: Path) -> None:
    required = FakeAsyncSink()
    optional = FakeAsyncSink(fail_write=True)
    manager = _manager(tmp_path, req=(required, True), opt=(optional, False))
    event = _ne()

    result = await manager.process(event)

    assert result is event  # the event survives; only the optional sink failed
    assert DeadLetterQueue(_settings(tmp_path)).stats()["total"] == 0


async def test_one_sinks_failure_does_not_prevent_the_others_from_writing(tmp_path: Path) -> None:
    broken = FakeAsyncSink(fail_write=True)
    healthy_required = FakeAsyncSink()
    healthy_optional = FakeAsyncSink()
    manager = _manager(
        tmp_path,
        broken=(broken, False),
        req=(healthy_required, True),
        opt=(healthy_optional, False),
    )
    event = _ne()

    result = await manager.process(event)

    assert result is event
    assert healthy_required.writes == [event] and healthy_optional.writes == [event]


# --------------------------------------------------------------------------
# lifecycle: start / flush(=close)


async def test_start_starts_every_sink_and_survives_one_failing(tmp_path: Path) -> None:
    ok = FakeAsyncSink()
    broken = FakeAsyncSink(fail_start=True)
    manager = _manager(tmp_path, ok=(ok, True), broken=(broken, False))

    await manager.start()  # must not raise

    assert ok.started is True
    assert broken.started is False  # its start() raised, but the manager survives


async def test_flush_closes_every_sink_and_survives_one_failing(tmp_path: Path) -> None:
    ok = FakeAsyncSink()

    class BrokenClose(FakeAsyncSink):
        async def close(self) -> None:
            raise RuntimeError("close failed")

    broken = BrokenClose()
    manager = _manager(tmp_path, ok=(ok, True), broken=(broken, False))

    await manager.flush()  # must not raise

    assert ok.closed is True


async def test_close_is_an_alias_for_flush(tmp_path: Path) -> None:
    ok = FakeAsyncSink()
    manager = _manager(tmp_path, ok=(ok, True))
    await manager.close()
    assert ok.closed is True


# --------------------------------------------------------------------------
# the real, synchronous ParquetSink wrapped off-thread


async def test_sync_parquet_sink_is_wrapped_and_actually_writes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    parquet = ParquetSink(settings, max_rows=1)  # auto-flushes on the very first row
    manager = SinkManager(settings)
    manager.register(SinkHandle.for_sync_sink("parquet", parquet, required=True))

    result = await manager.process(_ne())

    assert result is not None
    files = list((tmp_path / "silver").rglob("*.parquet"))
    assert len(files) == 1
