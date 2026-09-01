"""Tests for :mod:`ulpf.core.models` — the cross-stage data contracts."""

from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from ulpf.core.models import (
    DeadLetter,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
    sha256_hex,
)

# Deliberately not valid UTF-8, to prove bytes survive JSON round-trips.
_RAW = b"\xff\xfe<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built connection\x00"


def _raw_event() -> RawEvent:
    return RawEvent.from_raw(
        _RAW,
        source_id="asa-dmz-1",
        transport="udp",
        ingest_time_ns=1_697_062_455_000_000_000,
        peer="203.0.113.9",
    )


def test_from_raw_derives_hash_and_len() -> None:
    ev = _raw_event()
    assert ev.raw == _RAW
    assert ev.raw_len == len(_RAW)
    assert ev.raw_hash == hashlib.sha256(_RAW).hexdigest()
    assert ev.raw_hash == sha256_hex(_RAW)
    assert len(ev.event_uid) == 36


def test_raw_event_json_roundtrip_preserves_bytes() -> None:
    ev = _raw_event()
    restored = RawEvent.model_validate_json(ev.model_dump_json())
    assert restored == ev
    assert restored.raw == _RAW  # exact bytes, including \xff and NUL


def test_raw_event_python_roundtrip_preserves_bytes() -> None:
    ev = _raw_event()
    restored = RawEvent.model_validate(ev.model_dump())
    assert restored.raw == _RAW
    assert restored == ev


def test_invalid_transport_rejected() -> None:
    with pytest.raises(ValidationError):
        RawEvent.from_raw(
            _RAW,
            source_id="x",
            transport="carrier-pigeon",  # type: ignore[arg-type]
            ingest_time_ns=0,
        )


def test_parsed_event_extends_raw_and_roundtrips() -> None:
    base = _raw_event()
    parsed = ParsedEvent(
        **base.model_dump(),
        format="syslog",
        source_type="cisco_asa",
        fields={"action": "Built", "src_ip": "10.1.1.5"},
        envelope={"pri": 134, "host": "fw01"},
    )
    assert parsed.raw == _RAW
    assert parsed.template_id is None
    restored = ParsedEvent.model_validate_json(parsed.model_dump_json())
    assert restored == parsed
    assert restored.fields["src_ip"] == "10.1.1.5"


def test_normalized_event_traceability_is_requirement_d() -> None:
    base = _raw_event()
    norm = NormalizedEvent(
        event_uid=base.event_uid,
        raw_hash=base.raw_hash,
        ingest_time_ns=base.ingest_time_ns,
        ocsf={"class_uid": 4001, "activity_id": 1},
        source_type="cisco_asa",
        mapping_version="2025.09.0",
    )
    assert norm.traceability() == {
        "event_uid": base.event_uid,
        "raw_hash": base.raw_hash,
    }
    restored = NormalizedEvent.model_validate_json(norm.model_dump_json())
    assert restored == norm
    assert restored.traceability() == norm.traceability()


def test_dead_letter_roundtrip_preserves_raw() -> None:
    base = _raw_event()
    dl = DeadLetter(
        event_uid=base.event_uid,
        raw=_RAW,
        raw_hash=base.raw_hash,
        reason="no source_type matched",
        stage="detect",
        detail={"candidates": ["cisco_asa", "generic_syslog"]},
        ts_ns=base.ingest_time_ns,
    )
    restored = DeadLetter.model_validate_json(dl.model_dump_json())
    assert restored == dl
    assert restored.raw == _RAW
    assert restored.detail["candidates"] == ["cisco_asa", "generic_syslog"]
