"""Tests for :mod:`ulpf.ingest.queue`."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from ulpf.config.settings import IngestSettings, Settings
from ulpf.core.errors import IngestError
from ulpf.core.metrics import snapshot
from ulpf.ingest.queue import BoundedEventQueue, PutOutcome


def _queue(max_size: int, **kwargs: Any) -> BoundedEventQueue:
    settings = Settings(ingest=IngestSettings(queue_max_size=max_size))
    return BoundedEventQueue(settings, **kwargs)


async def test_fifo_roundtrip_and_depth() -> None:
    q = _queue(4)
    for n in range(3):
        assert await q.put_with_backpressure(n) is PutOutcome.ENQUEUED
    assert q.depth() == 3
    assert [await q.get() for _ in range(3)] == [0, 1, 2]
    assert q.depth() == 0


async def test_depth_is_wired_to_gauge() -> None:
    q = _queue(8)
    await q.put_with_backpressure("a")
    await q.put_with_backpressure("b")
    assert snapshot()["ulpf_queue_depth"] == float(q.depth()) == 2.0


async def test_producer_blocks_when_full_and_queue_stays_bounded() -> None:
    q = _queue(2)
    await q.put_with_backpressure(1)
    await q.put_with_backpressure(2)
    assert q.depth() == 2

    producer = asyncio.create_task(q.put_with_backpressure(3))
    await asyncio.sleep(0.05)
    assert not producer.done()  # producer is blocked, not dropped
    assert q.depth() == 2  # bounded: it did NOT grow to 3
    assert len(q) == 2

    assert await q.get() == 1  # free one slot
    assert await asyncio.wait_for(producer, timeout=1) is PutOutcome.ENQUEUED
    assert q.depth() == 2
    assert [await q.get() for _ in range(2)] == [2, 3]  # nothing lost, order kept


async def test_backpressure_metric_only_increments_when_waiting() -> None:
    q = _queue(1)
    key = "ulpf_queue_backpressure_waits_total"
    before = snapshot().get(key, 0.0)

    await q.put_with_backpressure("first")  # fits immediately
    assert snapshot().get(key, 0.0) == before

    producer = asyncio.create_task(q.put_with_backpressure("second"))
    await asyncio.sleep(0.05)
    assert snapshot()[key] - before == 1.0  # the wait was counted

    await q.get()
    await asyncio.wait_for(producer, timeout=1)


async def test_block_policy_timeout_raises_and_keeps_bounded() -> None:
    q = _queue(1)
    await q.put_with_backpressure("x")
    with pytest.raises(IngestError):
        await q.put_with_backpressure("y", timeout=0.05)
    assert q.depth() == 1
    assert await q.get() == "x"


async def test_dlq_policy_diverts_overflow_without_dropping() -> None:
    diverted: list[Any] = []

    async def handler(item: Any) -> None:
        diverted.append(item)

    q = _queue(1, drop_policy="dlq", dlq_handler=handler)
    dl_key = 'ulpf_dead_letter_total{reason="queue_full",stage="ingest"}'
    before = snapshot().get(dl_key, 0.0)

    await q.put_with_backpressure("keep")
    outcome = await q.put_with_backpressure("overflow", timeout=0.05)

    assert outcome is PutOutcome.DEAD_LETTERED
    assert diverted == ["overflow"]  # persisted, not discarded
    assert q.depth() == 1  # capacity never exceeded
    assert snapshot()[dl_key] - before == 1.0


def test_dlq_policy_requires_a_handler() -> None:
    with pytest.raises(ValueError):
        _queue(1, drop_policy="dlq")


async def test_dlq_handler_untouched_on_fast_path() -> None:
    calls: list[Any] = []

    async def handler(item: Any) -> None:
        calls.append(item)

    q = _queue(3, drop_policy="dlq", dlq_handler=handler)
    await q.put_with_backpressure("a")
    await q.put_with_backpressure("b")
    assert calls == []
    assert q.depth() == 2
