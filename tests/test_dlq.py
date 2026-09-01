"""Tests for :mod:`ulpf.sinks.dlq`."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.integrity.hashing import make_raw_event
from ulpf.sinks.dlq import DeadLetterQueue

_DAY_NS = 86_400 * 1_000_000_000
_BASE_NS = int(dt.datetime(2023, 10, 11, tzinfo=dt.UTC).timestamp()) * 1_000_000_000


class _Clock:
    """A settable epoch-nanoseconds clock."""

    def __init__(self, start: int) -> None:
        self.t = start

    def __call__(self) -> int:
        return self.t

    def advance(self, ns: int) -> None:
        self.t += ns


def _dlq(tmp_path: Path, clock: _Clock | None = None) -> DeadLetterQueue:
    settings = Settings(storage=StorageSettings(dlq_path=tmp_path / "dlq"))
    if clock is None:
        return DeadLetterQueue(settings)
    return DeadLetterQueue(settings, clock=clock)


def _raw(i: int):  # noqa: ANN202 - RawEvent
    return make_raw_event(f"line {i} \xff".encode("latin-1"), source_id="s", transport="udp")


def test_write_creates_partitioned_ndjson(tmp_path: Path) -> None:
    clk = _Clock(_BASE_NS)
    q = _dlq(tmp_path, clk)
    rec = q.write(_raw(1), reason="unsniffable", stage="detect", detail={"tried": ["a", "b"]})

    path = tmp_path / "dlq" / "date=2023-10-11" / "deadletters.ndjson"
    assert path.is_file()
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1

    (back,) = list(q.iter_recent(1))
    assert back.event_uid == rec.event_uid
    assert back.reason == "unsniffable"
    assert back.stage == "detect"
    assert back.detail == {"tried": ["a", "b"]}
    assert back.raw == rec.raw


def test_write_increments_dead_letter_metric(tmp_path: Path) -> None:
    q = _dlq(tmp_path)
    key = 'ulpf_dead_letter_total{reason="dlq_test_reason",stage="dlq_test_stage"}'
    before = snapshot().get(key, 0.0)
    q.write(_raw(1), reason="dlq_test_reason", stage="dlq_test_stage")
    assert snapshot()[key] - before == 1.0


def test_iter_recent_is_newest_first_and_limited(tmp_path: Path) -> None:
    clk = _Clock(_BASE_NS)
    q = _dlq(tmp_path, clk)
    written = []
    for i in range(5):
        written.append(q.write(_raw(i), reason="grok_timeout", stage="parse"))
        clk.advance(60 * 1_000_000_000)

    recent = list(q.iter_recent(3))
    assert [r.event_uid for r in recent] == [w.event_uid for w in reversed(written)][:3]


def test_iter_recent_spans_date_partitions(tmp_path: Path) -> None:
    clk = _Clock(_BASE_NS)
    q = _dlq(tmp_path, clk)
    a1 = q.write(_raw(1), reason="unsniffable", stage="detect")
    clk.advance(3600 * 1_000_000_000)
    a2 = q.write(_raw(2), reason="unsniffable", stage="detect")
    clk.advance(_DAY_NS)  # roll to the next day
    b1 = q.write(_raw(3), reason="grok_timeout", stage="parse")
    clk.advance(60 * 1_000_000_000)
    b2 = q.write(_raw(4), reason="mapping_error", stage="normalize")

    assert (tmp_path / "dlq" / "date=2023-10-11" / "deadletters.ndjson").is_file()
    assert (tmp_path / "dlq" / "date=2023-10-12" / "deadletters.ndjson").is_file()

    recent = [r.event_uid for r in q.iter_recent(3)]
    assert recent == [b2.event_uid, b1.event_uid, a2.event_uid]
    assert a1.event_uid not in recent


def test_stats_groups_by_reason_and_stage(tmp_path: Path) -> None:
    q = _dlq(tmp_path)
    q.write(_raw(1), reason="grok_timeout", stage="parse")
    q.write(_raw(2), reason="grok_timeout", stage="parse")
    q.write(_raw(3), reason="unsniffable", stage="detect")
    q.write(_raw(4), reason="mapping_error", stage="normalize")

    stats = q.stats()
    assert stats["total"] == 4
    assert stats["by_reason"] == {"grok_timeout": 2, "unsniffable": 1, "mapping_error": 1}
    assert stats["by_stage"] == {"parse": 2, "detect": 1, "normalize": 1}


def test_iter_recent_non_positive_limit_yields_nothing(tmp_path: Path) -> None:
    q = _dlq(tmp_path)
    q.write(_raw(1), reason="unsniffable", stage="detect")
    assert list(q.iter_recent(0)) == []
    assert list(q.iter_recent(-5)) == []


def test_dlq_refuses_overwriting_open_modes(tmp_path: Path) -> None:
    q = _dlq(tmp_path)
    for mode in ("w", "r+", "wb", "a+", "x"):
        with pytest.raises(AssertionError):
            q._open(tmp_path / "x.ndjson", mode)


def test_invalid_utf8_bytes_survive_the_dlq(tmp_path: Path) -> None:
    bad = b"\xff\xfe bad \x00 utf8 \xc3\x28 tail"
    event = make_raw_event(bad, source_id="s", transport="tcp")
    q = _dlq(tmp_path)
    q.write(event, reason="unsniffable", stage="detect")

    (back,) = list(q.iter_recent(1))
    assert back.raw == bad
    assert back.raw_hash == event.raw_hash
