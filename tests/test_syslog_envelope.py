"""Tests for :mod:`ulpf.parse.syslog_envelope`."""

from __future__ import annotations

from ulpf.parse.syslog_envelope import parse_syslog_envelope

# Canonical examples from RFC 5424 section 6.5.
_RFC5424_1 = (
    b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - "
    b"'su root' failed for lonvick on /dev/pts/8"
)
_RFC5424_2 = (
    b"<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - "
    b"%% It's time to make the do-nuts."
)
_RFC5424_3 = (
    b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    b'[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] '
    b"\xef\xbb\xbfAn application event log entry..."
)
_RFC5424_4 = (
    b"<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 "
    b'[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'
    b'[examplePriority@32473 class="high"]'
)
# Canonical RFC 3164 example (section 5.4).
_RFC3164 = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"


def _reassembles(raw: bytes) -> bool:
    env, msg = parse_syslog_envelope(raw)
    return env["header_raw"].encode("latin-1") + msg == raw


def test_no_pri_returns_empty_envelope_and_whole_line() -> None:
    raw = b"a plain line with no priority prefix at all"
    env, msg = parse_syslog_envelope(raw)
    assert env == {}
    assert msg == raw


def test_pri_decoding_facility_and_severity() -> None:
    env, _ = parse_syslog_envelope(_RFC5424_1)
    assert env["pri"] == 34
    assert env["pri_raw"] == "<34>"
    assert env["facility"] == 4 and env["facility_name"] == "auth"
    assert env["severity"] == 2 and env["severity_name"] == "Critical"

    env2, _ = parse_syslog_envelope(_RFC5424_2)
    assert env2["pri"] == 165
    assert env2["facility"] == 20 and env2["facility_name"] == "local4"
    assert env2["severity"] == 5 and env2["severity_name"] == "Notice"


def test_rfc5424_example_1_nilvalues() -> None:
    env, msg = parse_syslog_envelope(_RFC5424_1)
    assert env["format"] == "rfc5424"
    assert env["version"] == 1
    assert env["timestamp"] == "2003-10-11T22:14:15.003Z"
    assert env["hostname"] == "mymachine.example.com"
    assert env["app_name"] == "su"
    assert env["procid"] is None and env["procid_raw"] == "-"
    assert env["msgid"] == "ID47"
    assert env["structured_data"] is None and env["structured_data_raw"] == "-"
    assert msg == b"'su root' failed for lonvick on /dev/pts/8"
    assert _reassembles(_RFC5424_1)


def test_rfc5424_example_2_procid_and_msg() -> None:
    env, msg = parse_syslog_envelope(_RFC5424_2)
    assert env["hostname"] == "192.0.2.1"
    assert env["app_name"] == "myproc"
    assert env["procid"] == "8710"
    assert env["msgid"] is None
    assert env["structured_data"] is None
    assert msg == b"%% It's time to make the do-nuts."
    assert _reassembles(_RFC5424_2)


def test_rfc5424_structured_data_parsed_to_nested_dict() -> None:
    env, msg = parse_syslog_envelope(_RFC5424_3)
    assert env["structured_data"] == {
        "exampleSDID@32473": {
            "iut": "3",
            "eventSource": "Application",
            "eventID": "1011",
        }
    }
    assert env["structured_data_raw"] == (
        '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]'
    )
    # BOM and message bytes are preserved exactly, nothing decoded.
    assert msg == b"\xef\xbb\xbfAn application event log entry..."
    assert _reassembles(_RFC5424_3)


def test_rfc5424_multiple_sd_elements_and_no_msg() -> None:
    env, msg = parse_syslog_envelope(_RFC5424_4)
    assert env["structured_data"] == {
        "exampleSDID@32473": {"iut": "3", "eventSource": "Application", "eventID": "1011"},
        "examplePriority@32473": {"class": "high"},
    }
    assert msg == b""
    assert _reassembles(_RFC5424_4)


def test_rfc5424_escapes_in_structured_data_values() -> None:
    raw = b'<14>1 - - - - - [ex@1 a="say \\"hi\\"" b="c\\\\d" c="x\\]y"] body'
    env, msg = parse_syslog_envelope(raw)
    assert env["structured_data"] == {"ex@1": {"a": 'say "hi"', "b": "c\\d", "c": "x]y"}}
    assert msg == b"body"
    assert _reassembles(raw)


def test_rfc3164_canonical_example() -> None:
    env, msg = parse_syslog_envelope(_RFC3164)
    assert env["format"] == "rfc3164"
    assert env["pri"] == 34
    assert env["timestamp"] == "Oct 11 22:14:15"
    assert env["hostname"] == "mymachine"
    assert env["tag"] == "su" and env["app_name"] == "su"
    assert env["procid"] is None
    assert msg == b"'su root' failed for lonvick on /dev/pts/8"
    assert _reassembles(_RFC3164)


def test_rfc3164_space_padded_day_and_pid_tag() -> None:
    raw = b"<13>Oct  1 09:05:00 gw01 dhclient[1234]: bound to 192.0.2.15"
    env, msg = parse_syslog_envelope(raw)
    assert env["timestamp"] == "Oct  1 09:05:00"  # two spaces preserved
    assert env["hostname"] == "gw01"
    assert env["tag"] == "dhclient"
    assert env["procid"] == "1234"
    assert msg == b"bound to 192.0.2.15"
    assert _reassembles(raw)


def test_pri_only_when_header_is_unrecognised() -> None:
    raw = b"<99>garbled header without a real timestamp here"
    env, msg = parse_syslog_envelope(raw)
    assert env["format"] == "pri_only"
    assert env["pri"] == 99
    assert env["header_raw"] == "<99>"
    assert msg == b"garbled header without a real timestamp here"
    assert _reassembles(raw)
