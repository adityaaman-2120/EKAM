"""Shared pytest fixtures for the ULPF test suite."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ulpf.config.settings import ParseSettings, Settings, StorageSettings
from ulpf.core.models import RawEvent

_TESTS_DIR = Path(__file__).parent
_FIXTURES_DIR = _TESTS_DIR / "fixtures"
_GOLDEN_DIR = _TESTS_DIR / "golden"


@pytest.fixture
def tmp_settings(tmp_path: Path) -> Settings:
    """A ``Settings`` whose storage and parser paths point inside ``tmp_path``.

    The runtime subdirectories (bronze/silver/dlq/ledger) and an empty sources
    directory are created so stages can write immediately.
    """
    runtime = tmp_path / "runtime"
    for name in ("bronze", "silver", "dlq", "ledger"):
        (runtime / name).mkdir(parents=True, exist_ok=True)
    sources_dir = tmp_path / "sources"
    sources_dir.mkdir(exist_ok=True)
    return Settings(
        storage=StorageSettings(
            bronze_path=runtime / "bronze",
            silver_path=runtime / "silver",
            dlq_path=runtime / "dlq",
            ledger_path=runtime / "ledger",
        ),
        parse=ParseSettings(sources_dir=sources_dir),
    )


@pytest.fixture
def sample_raw_event() -> RawEvent:
    """A representative Cisco ASA syslog line wrapped as a ``RawEvent``."""
    raw = (
        b"<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built outbound TCP "
        b"connection 8145 for outside:203.0.113.9/443 to inside:192.0.2.15/51234"
    )
    return RawEvent.from_raw(
        raw,
        source_id="asa-lab-1",
        transport="udp",
        ingest_time_ns=1_697_062_455_000_000_000,
        peer="203.0.113.9",
    )


@pytest.fixture
def load_golden() -> Callable[[str], Any]:
    """Return a loader for ``tests/golden/<name>.json`` (parsed JSON)."""

    def _load(name: str) -> Any:
        path = _GOLDEN_DIR / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    return _load


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to ``tests/fixtures/`` (synthetic sample logs)."""
    return _FIXTURES_DIR
