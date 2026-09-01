"""Tests for :mod:`ulpf.integrity.hashing`."""

from __future__ import annotations

import hashlib
import time

from ulpf.integrity.hashing import make_raw_event, sha256_hex

# Invalid UTF-8: lone 0xFF/0xFE, a bare continuation byte, and an embedded NUL.
_BAD_UTF8 = b"\xff\xfe<134>raw\x80event\x00 body \xc3\x28 tail"


def test_sha256_hex_matches_hashlib() -> None:
    assert sha256_hex(_BAD_UTF8) == hashlib.sha256(_BAD_UTF8).hexdigest()


def test_make_raw_event_preserves_invalid_utf8_bytes_exactly() -> None:
    before = time.time_ns()
    event = make_raw_event(_BAD_UTF8, source_id="fw-1", transport="udp", peer="203.0.113.9")
    after = time.time_ns()

    # Bytes stored verbatim — no decode, no strip.
    assert event.raw == _BAD_UTF8
    assert event.raw_len == len(_BAD_UTF8)

    # Hash is over the original bytes.
    assert event.raw_hash == hashlib.sha256(_BAD_UTF8).hexdigest()

    # Identity + ingest metadata.
    assert len(event.event_uid) == 36
    assert event.source_id == "fw-1"
    assert event.transport == "udp"
    assert event.peer == "203.0.113.9"
    assert before <= event.ingest_time_ns <= after


def test_make_raw_event_survives_json_roundtrip() -> None:
    event = make_raw_event(_BAD_UTF8, source_id="fw-1", transport="tcp")
    from ulpf.core.models import RawEvent

    restored = RawEvent.model_validate_json(event.model_dump_json())
    assert restored == event
    assert restored.raw == _BAD_UTF8
