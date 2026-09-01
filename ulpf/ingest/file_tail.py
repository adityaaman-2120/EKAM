"""File tailer for log files written by local sensors (Zeek, Suricata, ...).

:class:`FileTailer` follows one or more append-only log files the way ``tail -F``
does, and is the ingest path used for the demo's Zeek (``conn.log`` etc.) and
Suricata (``eve.json``) output. It:

* remembers a **byte offset per file** and persists it to
  ``<state_path>/tail_offsets.json`` so a restart resumes where it left off
  instead of re-reading (or missing) data;
* detects **rotation** by a change of inode and re-opens the path from offset 0;
  also handles in-place truncation (``copytruncate``) by noticing the file
  shrank below the saved offset;
* holds a **partial final line** — bytes with no trailing newline are buffered
  and not emitted until the newline arrives, so a half-written JSON record is
  never handed downstream.

Each complete line becomes a :class:`~ulpf.core.models.RawEvent` with
``transport="file"`` via :func:`~ulpf.integrity.hashing.make_raw_event`.

Polling (not inotify) is used deliberately: it is portable, and rotation/tail
semantics are easy to reason about and test. Data written to the old file in the
gap between a poll and a rotation can still be lost — keep ``poll_interval``
small for busy sources.
"""

from __future__ import annotations

import asyncio
import json
import logging
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from ulpf.config.settings import Settings
from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED
from ulpf.core.models import RawEvent
from ulpf.integrity.hashing import make_raw_event

_log = logging.getLogger(__name__)

OnEvent = Callable[[RawEvent], Awaitable[None]]
SourceIdOf = Callable[[Path], str]

_OFFSETS_FILE = "tail_offsets.json"
_DEFAULT_READ_SIZE = 1 << 20  # 1 MiB per read chunk while catching up


def _default_source_id(path: Path) -> str:
    """Default source id for a tailed file: its base name."""
    return path.name


def _split_lines(data: bytes) -> tuple[list[bytes], bytes]:
    """Split ``data`` into complete lines and a trailing partial remainder.

    A trailing ``\\r`` is stripped from each line; blank lines are dropped.
    """
    if b"\n" not in data:
        return [], data
    parts = data.split(b"\n")
    remainder = parts.pop()
    lines: list[bytes] = []
    for part in parts:
        line = part[:-1] if part.endswith(b"\r") else part
        if line:
            lines.append(line)
    return lines, remainder


@dataclass
class _FileState:
    """In-memory tail position for one file."""

    inode: int | None
    read_pos: int
    pending: bytes = b""


class FileTailer:
    """Tails a set of log files, following rotation, resuming across restarts."""

    def __init__(
        self,
        settings: Settings,
        *,
        poll_interval: float = 0.5,
        read_size: int = _DEFAULT_READ_SIZE,
        start_at_end: bool = False,
        source_id_of: SourceIdOf = _default_source_id,
    ) -> None:
        """Configure the tailer.

        Args:
            settings: Supplies ``storage.state_path`` for the offsets file.
            poll_interval: Seconds between scans in :meth:`watch`.
            read_size: Max bytes read per chunk while catching up.
            start_at_end: For a file with no saved offset, begin at EOF instead
                of reading it from the start.
            source_id_of: Maps a path to the ``source_id`` stamped on its events.
        """
        self._offsets_path = Path(settings.storage.state_path) / _OFFSETS_FILE
        self._poll_interval = poll_interval
        self._read_size = read_size
        self._start_at_end = start_at_end
        self._source_id_of = source_id_of
        self._paths: list[Path] = []
        self._on_event: OnEvent | None = None
        self._state: dict[Path, _FileState] = {}
        self._persisted: dict[str, dict[str, int]] = {}
        self._configured = False
        self._stopped = False

    async def watch(self, paths: list[str], on_event: OnEvent) -> None:
        """Tail ``paths`` forever, delivering each line to ``on_event``.

        Runs until :meth:`stop` is called or the task is cancelled; offsets are
        saved on every productive scan and once more on exit.
        """
        self._configure(paths, on_event)
        self._stopped = False
        try:
            while not self._stopped:
                await self._scan_all()
                if self._stopped:
                    break
                await asyncio.sleep(self._poll_interval)
        finally:
            self._save_offsets()

    async def poll_once(self, paths: list[str], on_event: OnEvent) -> int:
        """Do a single tail pass over ``paths`` and return the lines emitted.

        Loads persisted offsets on the first call; saves them before returning.
        Useful for one-shot/cron-style runs and for tests.
        """
        self._configure(paths, on_event)
        emitted = await self._scan_all()
        self._save_offsets()
        return emitted

    def stop(self) -> None:
        """Ask :meth:`watch` to exit after the current scan."""
        self._stopped = True

    # -- internals -------------------------------------------------------

    def _configure(self, paths: list[str], on_event: OnEvent) -> None:
        """Bind paths/callback and load persisted offsets, once."""
        if self._configured:
            return
        self._paths = [Path(p) for p in paths]
        self._on_event = on_event
        self._load_offsets()
        self._configured = True

    async def _scan_all(self) -> int:
        """Scan every watched path once; persist offsets if anything advanced."""
        total = 0
        for path in list(self._paths):
            total += await self._scan_file(path)
        if total:
            self._save_offsets()
        return total

    async def _scan_file(self, path: Path) -> int:
        """Reconcile one path's state with disk (rotation/truncation) then read."""
        try:
            st = path.stat()
        except (FileNotFoundError, NotADirectoryError):
            return 0
        if not stat.S_ISREG(st.st_mode):
            return 0

        state = self._state.get(path)
        if state is None:
            state = self._initial_state(path, st.st_ino, st.st_size)
            self._state[path] = state
        elif state.inode is not None and st.st_ino != state.inode:
            state = _FileState(inode=st.st_ino, read_pos=0)  # rotated: new inode
            self._state[path] = state
        elif st.st_size < state.read_pos:
            state.read_pos, state.pending = 0, b""  # truncated in place

        return await self._read_new(path, st.st_size, state)

    def _initial_state(self, path: Path, inode: int, size: int) -> _FileState:
        """First sight of a file: resume from a matching saved offset, else start fresh."""
        saved = self._persisted.get(str(path))
        if saved and saved.get("inode") == inode:
            return _FileState(inode=inode, read_pos=min(int(saved["offset"]), size))
        return _FileState(inode=inode, read_pos=size if self._start_at_end else 0)

    async def _read_new(self, path: Path, size: int, state: _FileState) -> int:
        """Read bytes past ``state.read_pos`` and emit each complete line."""
        if size <= state.read_pos:
            return 0
        remaining = size - state.read_pos
        emitted = 0
        with path.open("rb") as handle:
            handle.seek(state.read_pos)
            while remaining > 0:
                chunk = handle.read(min(self._read_size, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                state.read_pos += len(chunk)
                lines, state.pending = _split_lines(state.pending + chunk)
                for line in lines:
                    await self._emit(path, line)
                    emitted += 1
        return emitted

    async def _emit(self, path: Path, line: bytes) -> None:
        """Turn one line into a RawEvent, count it, and dispatch it."""
        EVENTS_RECEIVED.labels(transport="file").inc()
        BYTES_RECEIVED.labels(transport="file").inc(len(line))
        event = make_raw_event(
            line, source_id=self._source_id_of(path), transport="file", peer=None
        )
        assert self._on_event is not None
        try:
            await self._on_event(event)
        except Exception:  # noqa: BLE001 - a bad callback must not stop the tail
            _log.exception("file tail on_event failed", extra={"event_uid": event.event_uid})

    def _load_offsets(self) -> None:
        """Load ``tail_offsets.json`` into memory; tolerate missing/corrupt files."""
        try:
            text = self._offsets_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._persisted = {}
            return
        try:
            self._persisted = json.loads(text)
        except json.JSONDecodeError:
            _log.warning("corrupt tail offsets; ignoring", extra={"path": str(self._offsets_path)})
            self._persisted = {}

    def _save_offsets(self) -> None:
        """Atomically write committed offsets (read position minus the partial line)."""
        data = dict(self._persisted)
        for path, state in self._state.items():
            committed = max(0, state.read_pos - len(state.pending))
            data[str(path)] = {"inode": state.inode, "offset": committed}
        self._persisted = data
        self._offsets_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._offsets_path.with_name(self._offsets_path.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self._offsets_path)
