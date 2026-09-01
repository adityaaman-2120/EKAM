"""Tests for :mod:`ulpf.sinks.raw_store` — the bronze evidence tier."""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import json
from pathlib import Path

import pytest

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.models import RawEvent
from ulpf.sinks.raw_store import RawStore

_BASE_NS = 1_697_062_455_000_000_000  # 2023-10-11T22:14:15Z


def _store(tmp_path: Path, **kwargs: object) -> RawStore:
    settings = Settings(storage=StorageSettings(bronze_path=tmp_path / "bronze"))
    return RawStore(settings, **kwargs)  # type: ignore[arg-type]


def _event(i: int, ns: int = _BASE_NS) -> RawEvent:
    # Leading non-ASCII byte proves raw bytes survive the base64 round-trip.
    raw = bytes([i % 251]) + f" <134>Oct 11 22:14:15 fw01 %ASA-6-302013 msg {i}".encode()
    return RawEvent.from_raw(
        raw, source_id="asa-1", transport="udp", ingest_time_ns=ns + i, peer="203.0.113.9"
    )


def _disk_records(bronze: Path) -> list[dict]:
    out: list[dict] = []
    for path in sorted(bronze.rglob("events.ndjson.gz")):
        with gzip.open(path, "rb") as handle:
            out += [json.loads(line) for line in handle if line.strip()]
    return out


def test_write_100_read_back_and_verify(tmp_path: Path) -> None:
    store = _store(tmp_path, max_buffered_records=16, max_buffer_seconds=10_000)
    events = [_event(i) for i in range(100)]
    for event in events:
        store.write(event)
    store.flush()

    round_tripped = {e.event_uid: e for e in store.iter_all()}
    assert len(round_tripped) == 100
    for original in events:
        back = round_tripped[original.event_uid]
        assert back.raw == original.raw          # exact bytes
        assert back.raw_hash == original.raw_hash
        assert back.raw_len == original.raw_len
        assert store.read_by_uid(original.event_uid) == original
        assert store.verify(original.event_uid) is True


def test_partitioned_by_utc_ingest_date(tmp_path: Path) -> None:
    store = _store(tmp_path)
    d1 = int(dt.datetime(2023, 10, 11, 12, tzinfo=dt.UTC).timestamp()) * 10**9
    d2 = int(dt.datetime(2023, 10, 12, 1, tzinfo=dt.UTC).timestamp()) * 10**9
    a = RawEvent.from_raw(b"aaa", source_id="s", transport="tcp", ingest_time_ns=d1)
    b = RawEvent.from_raw(b"bbb", source_id="s", transport="tcp", ingest_time_ns=d2)
    store.write(a)
    store.write(b)
    store.flush()

    assert (tmp_path / "bronze" / "date=2023-10-11" / "events.ndjson.gz").is_file()
    assert (tmp_path / "bronze" / "date=2023-10-12" / "events.ndjson.gz").is_file()
    assert [e.event_uid for e in store.iter_all(date="2023-10-11")] == [a.event_uid]
    assert [e.event_uid for e in store.iter_all(date=dt.date(2023, 10, 12))] == [b.event_uid]


def test_autoflush_by_record_count(tmp_path: Path) -> None:
    store = _store(tmp_path, max_buffered_records=5, max_buffer_seconds=10_000)
    for i in range(5):
        store.write(_event(i))
    # The 5th write reaches the threshold and flushes without an explicit call.
    assert len(_disk_records(tmp_path / "bronze")) == 5


def test_autoflush_by_elapsed_time(tmp_path: Path) -> None:
    now = [0.0]
    store = _store(
        tmp_path, max_buffered_records=10_000, max_buffer_seconds=2.0, clock=lambda: now[0]
    )
    store.write(_event(1))
    assert _disk_records(tmp_path / "bronze") == []   # not yet flushed

    now[0] = 3.0
    store.write(_event(2))                            # elapsed 3s >= 2s -> flush
    assert len(_disk_records(tmp_path / "bronze")) == 2


def test_appends_across_flushes_never_overwrites(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.write(_event(1))
    store.flush()
    store.write(_event(2))
    store.flush()                                     # second gzip member appended
    assert len(list(store.iter_all())) == 2


def test_verify_detects_tampered_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    events = [_event(i) for i in range(10)]
    for event in events:
        store.write(event)
    store.flush()

    target = events[4]
    assert store.verify(target.event_uid) is True

    partition = next((tmp_path / "bronze").rglob("events.ndjson.gz"))
    with gzip.open(partition, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == target.event_uid:
            record["raw_b64"] = base64.b64encode(b"tampered-evidence").decode("ascii")
            # raw_hash deliberately left as-is -> digest mismatch
    # Rewrite the file directly; the store itself would never open "wb".
    with gzip.open(partition, "wb") as handle:
        for record in records:
            handle.write((json.dumps(record, sort_keys=True) + "\n").encode("utf-8"))

    assert store.verify(target.event_uid) is False
    assert store.verify(events[3].event_uid) is True   # neighbours unaffected
    assert store.verify(events[5].event_uid) is True


def test_missing_uid_reads_none_and_fails_verify(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.write(_event(1))
    store.flush()
    assert store.read_by_uid("00000000-0000-0000-0000-000000000000") is None
    assert store.verify("00000000-0000-0000-0000-000000000000") is False


def test_store_refuses_overwriting_open_modes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    for mode in ("wb", "w", "r+b", "a+b", "xb"):
        with pytest.raises(AssertionError):
            store._gzip(tmp_path / "x.ndjson.gz", mode)
