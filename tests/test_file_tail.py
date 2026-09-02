"""Tests for :mod:`ulpf.ingest.file_tail`."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.models import RawEvent
from ulpf.ingest.file_tail import FileTailer


class _Sink:
    def __init__(self) -> None:
        self.events: list[RawEvent] = []

    async def __call__(self, event: RawEvent) -> None:
        self.events.append(event)

    @property
    def raws(self) -> list[bytes]:
        return [e.raw for e in self.events]


def _tailer(tmp_path: Path, **kwargs: object) -> FileTailer:
    settings = Settings(storage=StorageSettings(state_path=tmp_path / "state"))
    return FileTailer(settings, poll_interval=0.01, **kwargs)  # type: ignore[arg-type]


async def test_tails_new_and_appended_lines(tmp_path: Path) -> None:
    log = tmp_path / "conn.log"
    log.write_bytes(b"line a\nline b\n")
    sink = _Sink()
    tailer = _tailer(tmp_path)

    assert await tailer.poll_once([str(log)], sink) == 2
    assert sink.raws == [b"line a", b"line b"]
    assert all(e.transport == "file" and e.source_id == "conn.log" for e in sink.events)
    assert sink.events[0].raw_hash == hashlib.sha256(b"line a").hexdigest()

    with log.open("ab") as fh:
        fh.write(b"line c\nline d\n")
    assert await tailer.poll_once([str(log)], sink) == 2
    assert sink.raws == [b"line a", b"line b", b"line c", b"line d"]


async def test_partial_final_line_held_until_newline(tmp_path: Path) -> None:
    log = tmp_path / "eve.json"
    log.write_bytes(b'{"a":1}\n{"partial":')
    sink = _Sink()
    tailer = _tailer(tmp_path)

    assert await tailer.poll_once([str(log)], sink) == 1
    assert sink.raws == [b'{"a":1}']

    with log.open("ab") as fh:
        fh.write(b"2}\n")
    assert await tailer.poll_once([str(log)], sink) == 1
    assert sink.raws == [b'{"a":1}', b'{"partial":2}']


async def test_offsets_persist_across_restart(tmp_path: Path) -> None:
    log = tmp_path / "conn.log"
    log.write_bytes(b"a\nb\nc\n")

    first = _tailer(tmp_path)
    assert await first.poll_once([str(log)], _Sink()) == 3

    with log.open("ab") as fh:
        fh.write(b"d\ne\n")

    # A brand-new tailer instance sharing the same state dir must resume, not replay.
    resumed_sink = _Sink()
    second = _tailer(tmp_path)
    assert await second.poll_once([str(log)], resumed_sink) == 2
    assert resumed_sink.raws == [b"d", b"e"]

    offsets = json.loads((tmp_path / "state" / "tail_offsets.json").read_text())
    assert offsets[str(log)]["offset"] == len(b"a\nb\nc\nd\ne\n")


async def test_rotation_by_inode_reopens_from_zero(tmp_path: Path) -> None:
    log = tmp_path / "conn.log"
    log.write_bytes(b"old one\nold two\n")
    sink = _Sink()
    tailer = _tailer(tmp_path)
    assert await tailer.poll_once([str(log)], sink) == 2

    # Rotate: move the current file aside, create a fresh one (new inode),
    # with a LONGER body so only inode-change detection can explain re-reading it.
    log.rename(tmp_path / "conn.log.1")
    log.write_bytes(b"fresh one\nfresh two\nfresh three\n")

    assert await tailer.poll_once([str(log)], sink) == 3
    assert sink.raws == [
        b"old one",
        b"old two",
        b"fresh one",
        b"fresh two",
        b"fresh three",
    ]
    offsets = json.loads((tmp_path / "state" / "tail_offsets.json").read_text())
    assert offsets[str(log)]["offset"] == len(b"fresh one\nfresh two\nfresh three\n")


async def test_in_place_truncation_restarts_from_zero(tmp_path: Path) -> None:
    log = tmp_path / "conn.log"
    log.write_bytes(b"aaaa\nbbbb\n")
    sink = _Sink()
    tailer = _tailer(tmp_path)
    assert await tailer.poll_once([str(log)], sink) == 2

    # copytruncate style: same inode, file shrinks.
    log.write_bytes(b"cccc\n")
    assert await tailer.poll_once([str(log)], sink) == 1
    assert sink.raws == [b"aaaa", b"bbbb", b"cccc"]


async def test_missing_file_is_tolerated_then_picked_up(tmp_path: Path) -> None:
    log = tmp_path / "not-yet.log"
    sink = _Sink()
    tailer = _tailer(tmp_path)

    assert await tailer.poll_once([str(log)], sink) == 0  # no error

    log.write_bytes(b"hello\nworld\n")
    assert await tailer.poll_once([str(log)], sink) == 2
    assert sink.raws == [b"hello", b"world"]


async def test_multiple_files_with_distinct_source_ids(tmp_path: Path) -> None:
    a = tmp_path / "conn.log"
    b = tmp_path / "dns.log"
    a.write_bytes(b"c1\nc2\n")
    b.write_bytes(b"d1\n")
    sink = _Sink()

    emitted = await _tailer(tmp_path).poll_once([str(a), str(b)], sink)
    assert emitted == 3
    by_source: dict[str, list[bytes]] = {}
    for event in sink.events:
        by_source.setdefault(event.source_id, []).append(event.raw)
    assert by_source == {"conn.log": [b"c1", b"c2"], "dns.log": [b"d1"]}


async def test_crlf_stripped_and_empty_lines_skipped(tmp_path: Path) -> None:
    log = tmp_path / "conn.log"
    log.write_bytes(b"first\r\n\r\nsecond\r\n")  # the empty middle line is dropped
    sink = _Sink()
    assert await _tailer(tmp_path).poll_once([str(log)], sink) == 2
    assert sink.raws == [b"first", b"second"]


async def test_watch_loop_runs_then_stops(tmp_path: Path) -> None:
    log = tmp_path / "eve.json"
    log.write_bytes(b'{"n":1}\n')
    sink = _Sink()
    tailer = _tailer(tmp_path)

    task = asyncio.create_task(tailer.watch([str(log)], sink))
    try:
        await asyncio.sleep(0.05)
        with log.open("ab") as fh:
            fh.write(b'{"n":2}\n{"n":3}\n')
        await asyncio.sleep(0.1)
    finally:
        tailer.stop()
        await asyncio.wait_for(task, timeout=2.0)

    assert sink.raws == [b'{"n":1}', b'{"n":2}', b'{"n":3}']
