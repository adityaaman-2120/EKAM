"""Tests for :class:`ulpf.core.pipeline.ParseStage`."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.metrics import snapshot
from ulpf.core.models import ParsedEvent, RawEvent
from ulpf.core.pipeline import ParseStage, Pipeline, RawStoreStage
from ulpf.integrity.hashing import make_raw_event
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.raw_store import RawStore

_ASA_LINE = (
    b"<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built outbound TCP connection 8145 "
    b"for outside:203.0.113.9/443 to inside:192.0.2.15/51234"
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ingest=IngestSettings(syslog_udp_port=0),
        pipeline=PipelineSettings(worker_count=1),
    )


def _raw(line: bytes) -> RawEvent:
    return make_raw_event(line, source_id="asa-1", transport="udp")


async def test_parse_stage_extracts_fields_from_json(tmp_path: Path) -> None:
    stage = ParseStage(_settings(tmp_path), ParseCoordinator())
    out = await stage.process(_raw(b'{"user":"admin","port":22}'))
    assert isinstance(out, ParsedEvent)
    assert out.format == "json"
    assert out.fields["user"] == "admin"
    assert out.fields["port"] == 22


async def test_parse_stage_cisco_asa_syslog_envelope_fields(tmp_path: Path) -> None:
    stage = ParseStage(_settings(tmp_path), ParseCoordinator())
    out = await stage.process(_raw(_ASA_LINE))
    assert isinstance(out, ParsedEvent)
    assert out.format == "unknown"  # the ASA message body is free text
    assert out.needs_template_mining is True
    assert out.fields["envelope.pri"] == 134
    assert out.fields["envelope.facility"] == 16
    assert out.fields["envelope.severity"] == 6
    assert out.fields["envelope.hostname"] == "fw01"
    assert out.fields["envelope.tag"] == "%ASA-6-302013"
    assert out.raw == _ASA_LINE  # raw bytes untouched


async def test_parse_error_is_dead_lettered_with_stage_parse(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    # 8+ commas -> sniffs as csv; no engine options -> csv engine raises -> ParseError
    stage = ParseStage(settings, ParseCoordinator(engine_options={}))
    raw = _raw(b"a,b,c,d,e,f,g,h,i")

    out = await stage.process(raw)
    assert out is None  # dropped from the pipeline, worker continues

    recent = list(DeadLetterQueue(settings).iter_recent(1))
    assert len(recent) == 1
    assert recent[0].stage == "parse"
    assert recent[0].raw == raw.raw
    assert recent[0].detail["format"] == "csv"


async def test_parse_success_rate_and_events_parsed_metrics(tmp_path: Path) -> None:
    stage = ParseStage(_settings(tmp_path), ParseCoordinator(engine_options={}))
    parsed_key = 'ulpf_events_parsed_total{source_type="unknown"}'
    before_parsed = snapshot().get(parsed_key, 0.0)

    for _ in range(3):
        await stage.process(_raw(b'{"a":1}'))
    assert snapshot()["ulpf_parse_success_rate"] == 1.0
    assert snapshot()[parsed_key] - before_parsed == 3.0

    await stage.process(_raw(b"a,b,c,d,e,f,g,h,i"))  # one failure
    assert snapshot()["ulpf_parse_success_rate"] == 0.75  # 3 / 4
    assert snapshot()[parsed_key] - before_parsed == 3.0  # unchanged on failure


async def test_cisco_asa_over_udp_reaches_parse_stage(tmp_path: Path) -> None:
    """End to end: an ASA syslog datagram is parsed with fields extracted."""
    from ulpf.ingest.syslog_udp import SyslogUdpListener

    settings = _settings(tmp_path)
    raw_store = RawStore(settings)
    seen: list[ParsedEvent] = []

    class _Recorder:
        name = "record"

        async def process(self, event: ParsedEvent) -> ParsedEvent:
            seen.append(event)
            return event

    pipeline = Pipeline(
        settings,
        [RawStoreStage(raw_store), ParseStage(settings, ParseCoordinator()), _Recorder()],
    )
    pipeline.start()
    listener = SyslogUdpListener(source_id="asa-dmz")
    await listener.start("127.0.0.1", 0, pipeline.submit)
    port = int(listener.sockname[1])

    loop = asyncio.get_running_loop()
    sender, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    try:
        sender.sendto(_ASA_LINE)
        await asyncio.sleep(0.2)
    finally:
        sender.close()
        await listener.stop()
        await pipeline.stop()

    assert len(seen) == 1
    parsed = seen[0]
    assert isinstance(parsed, ParsedEvent)
    assert parsed.raw == _ASA_LINE
    assert parsed.event_uid
    assert parsed.fields["envelope.pri"] == 134
    assert parsed.fields["envelope.hostname"] == "fw01"
    assert parsed.fields["envelope.tag"] == "%ASA-6-302013"
    assert parsed.fields["envelope.severity_name"] == "Informational"
    assert parsed.needs_template_mining is True
    assert len(list(raw_store.iter_all())) == 1  # also persisted to bronze
