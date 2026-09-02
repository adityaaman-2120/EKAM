"""Tests for :mod:`ulpf.normalize.stage`."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from ulpf.config.settings import Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.models import NormalizedEvent, ParsedEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.stage import NormalizeStage
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.dlq import DeadLetterQueue

_FORTI_LINE = (
    b'<189>date=2026-08-15 time=22:14:15 devname="FGT" action="accept" '
    b"srcip=192.0.2.15 srcport=51234 dstip=203.0.113.9 dstport=443 "
    b'level="notice" policyid=1'
)
_FORTI_FIELDS = {
    "date": "2026-08-15",
    "time": "22:14:15",
    "devname": "FGT",
    "action": "accept",
    "srcip": "192.0.2.15",
    "srcport": "51234",
    "dstip": "203.0.113.9",
    "dstport": "443",
    "level": "notice",
    "policyid": "1",
    "extra": "leftover",
}


def _full_source(*, on_failure: str = "dead_letter") -> dict[str, Any]:
    return {
        "name": "test_forti",
        "version": "1.2.0",
        "vendor": "Fortinet",
        "product": "FortiGate",
        "product_version": "7.4",
        "detect": {"contains": "devname="},
        "parse": {"engine": "kv", "options": {}},
        "normalize": {
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": {"from": "action", "map": {"accept": 6, "close": 2}, "default": 0},
            "fields": {
                "src_endpoint.ip": {"from": "srcip", "type": "ip"},
                "src_endpoint.port": {"from": "srcport", "type": "int"},
                "dst_endpoint.ip": {"from": "dstip", "type": "ip"},
                "dst_endpoint.port": {"from": "dstport", "type": "int"},
                "severity_id": {"from": "level", "map": {"notice": 1, "warning": 3}, "default": 1},
                "time": {
                    "from": ["date", "time"],
                    "type": "timestamp",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "tz": "UTC",
                },
            },
            "unmapped": "keep_all",
        },
        "validate": {"required": [], "on_failure": on_failure},
    }


def _incomplete_source(*, on_failure: str) -> dict[str, Any]:
    src = _full_source(on_failure=on_failure)
    # drop the src_endpoint mappings -> validate_4001 will flag it missing
    src["normalize"]["fields"] = {
        "dst_endpoint.ip": {"from": "dstip", "type": "ip"},
        "severity_id": {"from": "level", "map": {"notice": 1}, "default": 1},
        "time": {"from": "time", "type": "timestamp", "format": "%H:%M:%S", "default": 1},
    }
    return src


def _registry(tmp_path: Path, *definitions: dict[str, Any]) -> SourceRegistry:
    directory = tmp_path / "sources"
    directory.mkdir()
    for i, definition in enumerate(definitions):
        (directory / f"src_{i}.yaml").write_text(yaml.safe_dump(definition), encoding="utf-8")
    registry = SourceRegistry()
    registry.load_all(directory)
    return registry


def _settings(tmp_path: Path) -> Settings:
    return Settings(storage=StorageSettings(dlq_path=tmp_path / "dlq", bronze_path=tmp_path / "b"))


def _parsed(raw_bytes: bytes, fields: dict[str, Any]) -> ParsedEvent:
    raw = make_raw_event(raw_bytes, source_id="s", transport="udp")
    return ParsedEvent(**raw.model_dump(), format="kv", fields=fields)


async def test_matched_source_produces_a_normalized_ocsf_event(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = NormalizeStage(settings, _registry(tmp_path, _full_source()))
    event = _parsed(_FORTI_LINE, _FORTI_FIELDS)

    key = 'ulpf_events_normalized_total{class_uid="4001",source_type="test_forti"}'
    before = snapshot().get(key, 0.0)

    result = await stage.process(event)

    assert isinstance(result, NormalizedEvent)
    assert result.source_type == "test_forti"
    assert result.mapping_version == "1.2.0"
    assert result.event_uid == event.event_uid
    assert result.raw_hash == event.raw_hash
    ocsf = result.ocsf
    assert ocsf["class_uid"] == 4001 and ocsf["category_uid"] == 4
    assert ocsf["activity_id"] == 6
    assert ocsf["type_uid"] == 400106  # finalize applied
    assert ocsf["type_name"] == "Network Activity: Traffic"
    assert ocsf["src_endpoint"] == {"ip": "192.0.2.15", "port": 51234}
    assert ocsf["dst_endpoint"] == {"ip": "203.0.113.9", "port": 443}
    assert ocsf["metadata"]["uid"] == event.event_uid  # requirement (d)
    assert ocsf["unmapped"]["policyid"] == "1" and ocsf["unmapped"]["extra"] == "leftover"
    assert snapshot()[key] - before == 1.0


async def test_no_source_match_passes_through_as_unknown_without_dlq(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = NormalizeStage(settings, _registry(tmp_path, _full_source()))
    # raw text has no "devname=" -> nothing matches
    event = _parsed(b"<13>Oct 11 22:14:15 host something happened", {"a": "1", "b": "2"})

    result = await stage.process(event)

    assert isinstance(result, NormalizedEvent)
    assert result.source_type == "unknown"
    assert result.mapping_version == "none"
    assert result.ocsf["unmapped"] == {"a": "1", "b": "2"}
    assert result.ocsf["metadata"]["uid"] == event.event_uid
    assert DeadLetterQueue(settings).stats()["total"] == 0  # not dead-lettered


async def test_invalid_record_is_dead_lettered_when_on_failure_dead_letter(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = NormalizeStage(settings, _registry(tmp_path, _incomplete_source(on_failure="dead_letter")))
    event = _parsed(_FORTI_LINE, _FORTI_FIELDS)

    result = await stage.process(event)

    assert result is None  # dropped from the pipeline
    recent = list(DeadLetterQueue(settings).iter_recent(1))
    assert len(recent) == 1
    assert recent[0].stage == "normalize"
    assert recent[0].reason == "ocsf_validation_failed"
    assert recent[0].raw == event.raw
    assert recent[0].detail["source_type"] == "test_forti"
    assert any("src_endpoint" in e for e in recent[0].detail["errors"])


async def test_invalid_record_is_emitted_when_on_failure_warn(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    stage = NormalizeStage(settings, _registry(tmp_path, _incomplete_source(on_failure="warn")))
    event = _parsed(_FORTI_LINE, _FORTI_FIELDS)

    result = await stage.process(event)

    assert isinstance(result, NormalizedEvent)  # emitted despite failing validation
    assert result.source_type == "test_forti"
    assert DeadLetterQueue(settings).stats()["total"] == 0


async def test_first_matching_definition_wins_by_priority(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    low = _full_source()
    low["name"] = "specific"
    low["priority"] = 10
    high = _full_source()
    high["name"] = "generic"
    high["priority"] = 200
    stage = NormalizeStage(settings, _registry(tmp_path, high, low))

    result = await stage.process(_parsed(_FORTI_LINE, _FORTI_FIELDS))
    assert result is not None and result.source_type == "specific"
