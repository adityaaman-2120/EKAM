"""The Windows sample-generator script emits lines the REAL pipeline normalizes.

Runs ``scripts/win/send-sample.ps1 -DryRun`` and pushes each line through the
same :class:`~ulpf.core.pipeline.ParseStage` ->
:class:`~ulpf.normalize.stage.NormalizeStage` composition the live pipeline
uses -- not the ``ulpf inspect`` CLI helper. That helper reparses a line with
the matched definition's own engine regardless of what the sniff-based
``ParseStage`` produced, so a generator bug that only showed up in the real
pipeline (a cisco_asa line that matched but dead-lettered from
``ulpf.normalize.stage`` because the parser couldn't resolve a source IP) could
pass ``ulpf inspect`` while still failing in production -- as did
suricata_eve_alert's ``src_ip`` octet going out of range only past $i=55,
which a 20-line run never reached. Every source the generator supports gets
100 lines here; a single dead letter fails the suite.

Skipped anywhere PowerShell is not available (i.e. Linux CI); it is the local
Windows guard that stops the templates from drifting into malformed test data.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ulpf.config.settings import IngestSettings, PipelineSettings, Settings, StorageSettings
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import ParseStage
from ulpf.ingest.syslog_tcp import SyslogTcpListener
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.stage import NormalizeStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.dlq import DeadLetterQueue

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "win" / "send-sample.ps1"
_SOURCES = Path(__file__).resolve().parent.parent / "configs" / "sources"

_POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

pytestmark = pytest.mark.skipif(
    _POWERSHELL is None or not _SCRIPT.is_file(), reason="PowerShell / the script is not available"
)

# script -Source (canonical name)  ->  the source definition its lines must match
_EXPECT = {
    "cisco_asa": "cisco_asa",
    "fortigate_traffic": "fortigate_traffic",
    "panos_traffic_v10": "panos_traffic_v10",
    "panos_traffic_v11": "panos_traffic_v11",
    "suricata_eve_flow": "suricata_eve_flow",
    "suricata_eve_alert": "suricata_eve_alert",
    "zeek_conn": "zeek_conn",
    "zeek_dns": "zeek_dns",
    "zeek_http": "zeek_http",
    "aws_vpc_flow": "aws_vpc_flow",
    "iptables": "iptables",
}

_ALIASES = {
    "fortigate": "fortigate_traffic",
    "suricata": "suricata_eve_flow",
    "zeek": "zeek_conn",
    "panos": "panos_traffic_v10",
}


def _emit(source: str, count: int) -> list[str]:
    assert _POWERSHELL is not None  # guarded by pytestmark
    cmd = [
        _POWERSHELL,
        "-NoProfile",
        "-File",
        str(_SCRIPT),
        "-Source",
        source,
        "-Count",
        str(count),
        "-DryRun",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)  # noqa: S603
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


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


@pytest.fixture(scope="module")
def registry() -> SourceRegistry:
    reg = SourceRegistry()
    reg.load_all(_SOURCES)
    return reg


async def _run_raw_events_through_pipeline_async(
    events: list[RawEvent], registry: SourceRegistry, settings: Settings
) -> tuple[int, list[dict[str, Any]]]:
    """Push already-admitted ``events`` through ParseStage -> NormalizeStage.

    Returns ``(normalized_count, dlq_details)`` -- the same real pipeline
    composition production uses. ``len(dlq_details)`` is the dead-letter count.
    """
    parse_stage = ParseStage(settings, ParseCoordinator())
    normalize_stage = NormalizeStage(settings, registry)
    normalized_count = 0
    for raw in events:
        parsed = await parse_stage.process(raw)
        assert parsed is not None  # ParseStage never drops an event
        if await normalize_stage.process(parsed) is not None:
            normalized_count += 1
    dlq = DeadLetterQueue(settings)
    return normalized_count, [entry.detail for entry in dlq.iter_recent(len(events) + 1)]


def _run_raw_events_through_pipeline(
    events: list[RawEvent], registry: SourceRegistry, settings: Settings
) -> tuple[int, list[dict[str, Any]]]:
    """Synchronous wrapper for :func:`_run_raw_events_through_pipeline_async`."""
    return _run_sync(_run_raw_events_through_pipeline_async(events, registry, settings))


def _run_through_real_pipeline(
    lines: list[str], registry: SourceRegistry, settings: Settings
) -> list[dict[str, Any]]:
    """Push raw text ``lines`` through the real pipeline; see
    :func:`_run_raw_events_through_pipeline`. Returns just the DLQ details --
    ``len(...)`` of this is the ``dead_letter_count`` the test asserts is 0.
    """
    events = [
        make_raw_event(line.encode("utf-8"), source_id="send-sample-test", transport="udp")
        for line in lines
    ]
    _normalized_count, dlq_details = _run_raw_events_through_pipeline(events, registry, settings)
    return dlq_details


def _run_sync(coro: Any) -> Any:
    """Run an ``async def process(...)`` coroutine to completion, synchronously."""
    return asyncio.run(coro)


def _matched_definition_name(line: str, registry: SourceRegistry, settings: Settings) -> str | None:
    """Sniff-parse ``line`` (like the real pipeline) and return the matched source name."""
    raw = make_raw_event(line.encode("utf-8"), source_id="send-sample-test", transport="udp")
    parsed = _run_sync(ParseStage(settings, ParseCoordinator()).process(raw))
    definition = registry.match(parsed)
    return definition.name if definition is not None else None


_LINES_PER_SOURCE = 100


@pytest.mark.parametrize(("source", "expected"), sorted(_EXPECT.items()))
def test_hundred_lines_per_source_normalize_with_no_dead_letters(
    source: str, expected: str, registry: SourceRegistry, tmp_path: Path
) -> None:
    """The exact regression this suite exists to catch: a generator template

    that produces lines its own source definition matches but cannot fully
    normalize -- e.g. cisco_asa lines missing the inbound/outbound keyword and
    interface:addr/port structure the parser needs to resolve a source IP, or
    suricata_eve_alert emitting an out-of-range IPv4 octet (".399") once its
    index counter passed 55. Both bugs needed more than ~20 lines to surface,
    which is why this generates 100 per source rather than a token handful.
    """
    settings = _settings(tmp_path)
    lines = _emit(source, count=_LINES_PER_SOURCE)
    assert len(lines) == _LINES_PER_SOURCE
    assert len(set(lines)) == _LINES_PER_SOURCE  # -Count makes each line distinct

    for line in lines:
        assert _matched_definition_name(line, registry, settings) == expected, line

    dead_letters = _run_through_real_pipeline(lines, registry, settings)
    dead_letter_count = len(dead_letters)
    assert dead_letter_count == 0, (
        f"{source}: {dead_letter_count} of {_LINES_PER_SOURCE} lines dead-lettered: {dead_letters}"
    )


@pytest.mark.parametrize(("alias", "expected"), sorted(_ALIASES.items()))
def test_aliases_resolve_to_the_expected_canonical_source(
    alias: str, expected: str, registry: SourceRegistry, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    lines = _emit(alias, count=_LINES_PER_SOURCE)

    for line in lines:
        assert _matched_definition_name(line, registry, settings) == expected, line

    dead_letters = _run_through_real_pipeline(lines, registry, settings)
    assert dead_letters == []


def test_fortigate_line_is_bare_pri_no_rfc3164_stamp() -> None:
    (line,) = _emit("fortigate_traffic", count=1)
    # the whole point: `<189>` is followed immediately by `date=`, not by a
    # `Mon DD HH:MM:SS host` header that would be eaten as the syslog TAG.
    assert line.startswith("<189>date=")


def test_list_switch_prints_every_source_and_needs_no_source_argument() -> None:
    assert _POWERSHELL is not None  # guarded by pytestmark
    proc = subprocess.run(  # noqa: S603
        [_POWERSHELL, "-NoProfile", "-File", str(_SCRIPT), "-List"],
        capture_output=True,
        text=True,
        check=True,
    )
    for name in _EXPECT.values():
        assert name in proc.stdout


def test_validate_script_rejects_an_unknown_source() -> None:
    assert _POWERSHELL is not None  # guarded by pytestmark
    proc = subprocess.run(  # noqa: S603
        [_POWERSHELL, "-NoProfile", "-File", str(_SCRIPT), "-Source", "not_a_real_source"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0


# --------------------------------------------------------------------------
# real TCP wire test: sent == received == normalized, zero dead letters
#
# Every test above generates lines and feeds them into the pipeline stages
# in-process -- it never actually sends anything over a socket, so it cannot
# see transport loss. UDP syslog has none of TCP's delivery guarantees: a
# real verification run that sent 3300 events across these 11 sources over
# UDP with no pacing sealed only 513 (cisco_asa 300/300, zeek_dns 10/300) --
# the receive buffer overflowed under an unpaced burst. -Transport tcp is
# send-sample.ps1's default for exactly this reason. This section proves it:
# a real SyslogTcpListener, a real `-Transport tcp` subprocess send, and an
# assertion that nothing was lost between "sent" and "normalized".

# smaller than the 100-line in-process test above; this one pays for a real socket per source
_TCP_COUNT = 50


def _send_over_tcp(source: str, count: int, port: int) -> None:
    assert _POWERSHELL is not None  # guarded by pytestmark
    cmd = [
        _POWERSHELL,
        "-NoProfile",
        "-File",
        str(_SCRIPT),
        "-Source",
        source,
        "-Count",
        str(count),
        "-Transport",
        "tcp",
        "-Port",
        str(port),
    ]
    subprocess.run(cmd, capture_output=True, text=True, check=True)  # noqa: S603


@pytest.mark.parametrize(("source", "expected"), sorted(_EXPECT.items()))
async def test_tcp_transport_sent_equals_received_equals_normalized(
    source: str, expected: str, registry: SourceRegistry, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    received: list[RawEvent] = []

    async def _on_event(event: RawEvent) -> None:
        received.append(event)

    listener = SyslogTcpListener(source_id="win-send-sample-tcp-test")
    await listener.start("127.0.0.1", 0, _on_event)
    port = int(listener.sockname[1])
    try:
        await asyncio.to_thread(_send_over_tcp, source, _TCP_COUNT, port)
        # the sender's TCP connection is already closed by the time the
        # subprocess exits; give the listener's dispatch tasks a moment to
        # finish running (they are scheduled, not awaited, per datagram/frame)
        for _ in range(50):
            if len(received) >= _TCP_COUNT:
                break
            await asyncio.sleep(0.05)
    finally:
        await listener.stop()

    # sent == received: TCP guarantees reliable, in-order, lossless delivery
    assert len(received) == _TCP_COUNT, (
        f"{source}: sent {_TCP_COUNT} but only received {len(received)} over TCP"
    )

    match_stage = ParseStage(settings, ParseCoordinator())
    for event in received:
        parsed = await match_stage.process(event)
        assert parsed is not None
        definition = registry.match(parsed)
        assert definition is not None and definition.name == expected

    normalized_count, dlq_details = await _run_raw_events_through_pipeline_async(
        received, registry, settings
    )

    # received == normalized, zero dead letters
    assert dlq_details == [], f"{source}: {len(dlq_details)} dead-lettered: {dlq_details}"
    assert normalized_count == _TCP_COUNT == len(received)
