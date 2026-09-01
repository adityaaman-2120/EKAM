"""Tests for :mod:`ulpf.core.metrics`."""

from __future__ import annotations

from ulpf.core.metrics import (
    DEAD_LETTER,
    EVENTS_RECEIVED,
    QUEUE_DEPTH,
    snapshot,
    timed,
)


def test_counter_increment_shows_up_in_snapshot() -> None:
    key = 'ulpf_events_received_total{transport="udp"}'
    before = snapshot().get(key, 0.0)
    EVENTS_RECEIVED.labels(transport="udp").inc(3)
    assert snapshot()[key] - before == 3.0


def test_multi_label_counter_key_is_sorted() -> None:
    DEAD_LETTER.labels(stage="parse", reason="grok_timeout").inc()
    key = 'ulpf_dead_letter_total{reason="grok_timeout",stage="parse"}'
    assert snapshot()[key] >= 1.0


def test_gauge_set_is_reflected() -> None:
    QUEUE_DEPTH.set(42)
    assert snapshot()["ulpf_queue_depth"] == 42.0


def test_timed_records_one_stage_observation() -> None:
    count_key = 'ulpf_stage_latency_seconds_count{stage="unit-test"}'
    sum_key = 'ulpf_stage_latency_seconds_sum{stage="unit-test"}'
    before = snapshot().get(count_key, 0.0)

    with timed("unit-test"):
        pass

    snap = snapshot()
    assert snap[count_key] - before == 1.0
    assert snap[sum_key] >= 0.0


def test_snapshot_is_plain_dict_of_str_to_float() -> None:
    QUEUE_DEPTH.set(1)
    snap = snapshot()
    assert isinstance(snap, dict)
    assert all(isinstance(k, str) for k in snap)
    assert all(isinstance(v, float) for v in snap.values())
    assert "ulpf_queue_depth" in snap
    assert not any(k.endswith("_created") for k in snap)
