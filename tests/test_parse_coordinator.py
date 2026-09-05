"""Integration tests for :mod:`ulpf.parse.coordinator`."""

from __future__ import annotations

import pytest

from ulpf.core.errors import ParseError
from ulpf.core.models import ParsedEvent, RawEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.parse.coordinator import ParseCoordinator

_ENGINE_OPTIONS = {
    "csv": {"columns": [f"c{i}" for i in range(9)]},
    "tsv": {"columns": ["p", "q", "r", "s"]},
}


def _coordinator() -> ParseCoordinator:
    return ParseCoordinator(engine_options=_ENGINE_OPTIONS)


def _raw(line: bytes) -> RawEvent:
    return make_raw_event(line, source_id="test-src", transport="file")


def _parse(line: bytes) -> tuple[RawEvent, ParsedEvent]:
    raw = _raw(line)
    return raw, _coordinator().parse(raw)


def test_json_line() -> None:
    raw, parsed = _parse(b'{"event":"login","user":"admin","port":22}')
    assert parsed.format == "json"
    assert parsed.fields["user"] == "admin"
    assert parsed.fields["port"] == 22  # int type preserved
    assert parsed.envelope == {}
    assert parsed.needs_template_mining is False
    # raw bytes and identity carried through, untouched
    assert parsed.raw == raw.raw
    assert parsed.raw_hash == raw.raw_hash
    assert parsed.event_uid == raw.event_uid


def test_kv_line() -> None:
    _, parsed = _parse(b"action=allow src=10.0.0.1 dst=10.0.0.2 proto=tcp")
    assert parsed.format == "kv"
    assert parsed.fields["action"] == "allow"
    assert parsed.fields["src"] == "10.0.0.1"


def test_cef_line() -> None:
    _, parsed = _parse(
        b"CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
    )
    assert parsed.format == "cef"
    assert parsed.fields["deviceVendor"] == "Security"
    assert parsed.fields["src"] == "10.0.0.1"
    assert parsed.fields["spt"] == "1232"


def test_leef_line() -> None:
    _, parsed = _parse(
        b"LEEF:1.0|Lancope|StealthWatch|1.0|41|src=192.0.2.1\tdst=203.0.113.9\tsrcPort=3097"
    )
    assert parsed.format == "leef"
    assert parsed.fields["src"] == "192.0.2.1"
    assert parsed.fields["srcPort"] == "3097"


def test_csv_line_is_never_engine_dispatched_even_with_engine_options() -> None:
    """The sniff-based coordinator must not attempt a parse the definition owns.

    ``csv`` always needs a source's own ``columns``/``column_map`` (PAN-OS
    TRAFFIC's is version-keyed), so it is never engine-dispatched here even
    when the caller happens to have supplied matching ``engine_options`` --
    only :func:`~ulpf.parse.coordinator.parse_for_definition`, once a source
    definition has matched, is allowed to actually parse csv/tsv. Detecting it
    (for :class:`~ulpf.parse.dsl.loader.SourceRegistry` matching) is still the
    coordinator's job.
    """
    # >= 8 commas so the sniffer classifies it as csv
    _, parsed = _parse(b"1,2,3,4,5,6,7,8,9")
    assert parsed.format == "csv"
    assert parsed.fields == {}
    assert parsed.needs_template_mining is True


def test_tsv_line_is_never_engine_dispatched_even_with_engine_options() -> None:
    # >= 3 tabs so the sniffer classifies it as tsv
    _, parsed = _parse(b"w\tx\ty\tz")
    assert parsed.format == "tsv"
    assert parsed.fields == {}
    assert parsed.needs_template_mining is True


def test_csv_and_tsv_never_raise_regardless_of_options() -> None:
    """Not even a caller with NO engine_options sees a ParseError for csv/tsv.

    Before, this exact case ("csv" sniffed, no columns configured) raised —
    which is precisely the bug this design fixes: PAN-OS TRAFFIC would sniff
    as csv, raise "requires a 'columns' list" on every single event, and that
    logged an INFO line and corrupted ``ulpf_parse_success_rate`` /
    ``verify roundtrip``'s reparse_stable_rate for a perfectly healthy source.
    """
    coordinator = ParseCoordinator(engine_options={})
    parsed = coordinator.parse(_raw(b"a,b,c,d,e,f,g,h,i"))
    assert parsed.format == "csv"
    assert parsed.fields == {}


def test_bare_syslog_line_is_stripped_and_marked_for_drain3() -> None:
    _, parsed = _parse(b"<34>Oct 11 22:14:15 fw01 su: session opened for user root")
    assert parsed.format == "unknown"
    assert parsed.needs_template_mining is True
    assert parsed.fields == parsed.fields | {}  # engine fields are empty ...
    # ... but the envelope is preserved on the event and merged under envelope.*
    assert parsed.envelope["pri"] == 34
    assert parsed.envelope["hostname"] == "fw01"
    assert parsed.fields["envelope.pri"] == 34
    assert parsed.fields["envelope.facility_name"] == "auth"
    assert parsed.fields["envelope.tag"] == "su"


def test_syslog_wrapping_cef_dispatches_to_cef_and_keeps_envelope() -> None:
    _, parsed = _parse(
        b"<134>Sep 19 08:26:10 fw01 CEF:0|Vendor|Product|1.0|100|deny|5|"
        b"src=192.0.2.1 dst=203.0.113.9"
    )
    assert parsed.format == "cef"
    assert parsed.needs_template_mining is False
    assert parsed.fields["src"] == "192.0.2.1"  # from the CEF engine
    assert parsed.fields["envelope.pri"] == 134  # from the syslog envelope
    assert parsed.fields["envelope.hostname"] == "fw01"
    assert parsed.envelope["facility"] == 16


def test_unknown_line_yields_empty_fields_and_mining_flag() -> None:
    _, parsed = _parse(b"the quick brown fox jumps over the lazy dog")
    assert parsed.format == "unknown"
    assert parsed.fields == {}
    assert parsed.envelope == {}
    assert parsed.needs_template_mining is True


def test_engine_failure_is_reraised_as_parse_error_with_format() -> None:
    # kv IS engine-dispatched here (self-describing, config-free) -- but a
    # caller can still misconfigure its separators, and that must surface as
    # a real ParseError, not be silently swallowed like the csv/tsv case above.
    coordinator = ParseCoordinator(engine_options={"kv": {"kv_separator": ""}})
    with pytest.raises(ParseError) as exc_info:
        coordinator.parse(_raw(b"action=allow src=10.0.0.1 dst=10.0.0.2 proto=tcp"))
    assert exc_info.value.detail["format"] == "kv"
    assert "reason" in exc_info.value.detail


def test_parsed_event_round_trips_through_json() -> None:
    from ulpf.core.models import ParsedEvent

    _, parsed = _parse(b'{"a":1,"b":{"c":2}}')
    restored = ParsedEvent.model_validate_json(parsed.model_dump_json())
    assert restored == parsed


# --------------------------------------------------------------------------
# BUG 1: a leading BOM must not misroute detection, and must not touch evidence

_UTF8_BOM = b"\xef\xbb\xbf"
_JSON_LINE = b'{"event_type":"flow","src_ip":"192.0.2.15","dest_port":443}'


def test_utf8_bom_json_still_sniffs_as_json_and_parses() -> None:
    raw, parsed = _parse(_UTF8_BOM + _JSON_LINE)
    assert parsed.format == "json"  # not "csv"
    assert parsed.bom_stripped is True
    assert parsed.fields["src_ip"] == "192.0.2.15"
    assert parsed.fields["dest_port"] == 443


def test_bom_is_preserved_in_the_raw_bytes_and_hash() -> None:
    original = _UTF8_BOM + _JSON_LINE
    raw, parsed = _parse(original)
    # evidence is byte-for-byte, including the BOM
    assert raw.raw == original
    assert parsed.raw == original
    assert (
        parsed.raw_hash
        == raw.raw_hash
        == make_raw_event(original, source_id="x", transport="file").raw_hash
    )
    assert parsed.raw_len == len(original)  # BOM counted


def test_line_without_a_bom_is_unaffected() -> None:
    _, parsed = _parse(_JSON_LINE)
    assert parsed.format == "json"
    assert parsed.bom_stripped is False
    assert parsed.fields["src_ip"] == "192.0.2.15"


def test_utf8_bom_before_a_syslog_pri_still_detects_syslog() -> None:
    _, parsed = _parse(_UTF8_BOM + b"<134>x=1 y=2 z=3")
    assert parsed.format == "kv"  # inner format after the syslog envelope
    assert parsed.bom_stripped is True
    assert parsed.envelope.get("pri") == 134
