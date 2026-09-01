"""Strip and parse the syslog header (envelope) from a raw event.

``parse_syslog_envelope(raw)`` returns ``(envelope, message_bytes)`` where
``message_bytes`` is a slice of the *original* bytes — the header is removed but
nothing in the payload is decoded, re-encoded, or altered. When a header is
recognised the invariant

    envelope["header_raw"].encode("latin-1") + message_bytes == raw

holds, so the split is fully reversible.

Handled shapes:

* **PRI** ``<34>`` -> ``facility = 34 // 8``, ``severity = 34 % 8``, with name
  lookups (facility 0 kernel .. 23 local7; severity 0 Emergency .. 7 Debug).
* **RFC 5424** ``<PRI>VER TIMESTAMP HOST APP PROCID MSGID SD MSG`` — ``-`` is
  NILVALUE (parsed value ``None``, raw kept in ``*_raw``); structured data
  ``[id@ent key="value" ...][...]`` is parsed into a nested dict, with ``\\"``
  ``\\\\`` and ``\\]`` unescaped in values.
* **RFC 3164** ``<PRI>Mmm dd hh:mm:ss HOST TAG: MSG`` — the day may be
  space-padded (``Oct  1``); the original spacing is preserved in ``timestamp``.
* **No PRI** — returns an empty envelope ``{}`` and the whole line as the message.
"""

from __future__ import annotations

import re
from typing import Any

_FACILITY_NAMES: dict[int, str] = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "audit", 14: "alert", 15: "cron2",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}
_SEVERITY_NAMES: tuple[str, ...] = (
    "Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug",
)

_PRI_RE = re.compile(r"<(\d{1,3})>")
_VERSION_RE = re.compile(r"(\d{1,3}) ")
_RFC3164_RE = re.compile(r"([A-Za-z]{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) (\S+) ")
_TAG_RE = re.compile(r"([^\s:\[]{1,32})(?:\[(\d{1,10})\])?:?[ ]?")


def parse_syslog_envelope(raw: bytes) -> tuple[dict[str, Any], bytes]:
    """Split ``raw`` into a parsed syslog envelope and the remaining message bytes."""
    text = raw.decode("latin-1")  # 1:1, length-preserving -> char index == byte index
    pri_match = _PRI_RE.match(text)
    if pri_match is None:
        return {}, raw

    envelope = _pri_fields(int(pri_match.group(1)), pri_match.group(0))
    after_pri = pri_match.end()

    version = _VERSION_RE.match(text, after_pri)
    if version is not None:
        parsed = _parse_rfc5424(text, envelope, int(version.group(1)), version.end())
        if parsed is not None:
            done_env, msg_index = parsed
            return done_env, raw[msg_index:]

    header = _RFC3164_RE.match(text, after_pri)
    if header is not None:
        done_env, msg_index = _parse_rfc3164(text, envelope, header)
        return done_env, raw[msg_index:]

    envelope["format"] = "pri_only"
    envelope["header_raw"] = text[:after_pri]
    return envelope, raw[after_pri:]


def _pri_fields(pri: int, pri_raw: str) -> dict[str, Any]:
    """Return the facility/severity breakdown of a PRI value."""
    facility, severity = divmod(pri, 8)
    return {
        "pri": pri,
        "pri_raw": pri_raw,
        "facility": facility,
        "facility_name": _FACILITY_NAMES.get(facility, str(facility)),
        "severity": severity,
        "severity_name": _SEVERITY_NAMES[severity] if severity < 8 else str(severity),
    }


def _nil(value: str) -> str | None:
    """Map the RFC 5424 NILVALUE ``-`` to ``None``; pass everything else through."""
    return None if value == "-" else value


def _parse_rfc5424(
    text: str, envelope: dict[str, Any], version: int, body_start: int
) -> tuple[dict[str, Any], int] | None:
    """Parse an RFC 5424 header; return ``(envelope, msg_index)`` or ``None`` if malformed."""
    parts = text[body_start:].split(" ", 5)
    if len(parts) < 6:
        return None
    timestamp, hostname, app_name, procid, msgid, tail = parts
    tail_start = body_start + sum(len(p) + 1 for p in parts[:5])

    structured, sd_raw, msg_offset = _parse_structured_data(tail)
    msg_index = tail_start + msg_offset
    envelope.update(
        format="rfc5424",
        version=version,
        timestamp=_nil(timestamp), timestamp_raw=timestamp,
        hostname=_nil(hostname), hostname_raw=hostname,
        app_name=_nil(app_name), app_name_raw=app_name,
        procid=_nil(procid), procid_raw=procid,
        msgid=_nil(msgid), msgid_raw=msgid,
        structured_data=structured, structured_data_raw=sd_raw,
        header_raw=text[:msg_index],
    )
    return envelope, msg_index


def _parse_structured_data(tail: str) -> tuple[dict[str, dict[str, str]] | None, str, int]:
    """Parse the STRUCTURED-DATA field at the head of ``tail``.

    Returns ``(parsed_or_None, raw_text, message_offset)`` where ``message_offset``
    is the index within ``tail`` at which MSG begins.
    """
    if tail[:1] == "-" and (len(tail) == 1 or tail[1] == " "):
        return None, "-", 2 if len(tail) > 1 else 1
    if tail[:1] != "[":
        return None, "", 0  # malformed SD: treat the whole tail as MSG

    elements: dict[str, dict[str, str]] = {}
    index = 0
    while index < len(tail) and tail[index] == "[":
        index, sd_id, params = _scan_sd_element(tail, index)
        elements[sd_id] = params
    sd_raw = tail[:index]
    if index < len(tail) and tail[index] == " ":
        return elements, sd_raw, index + 1
    return elements, sd_raw, index


def _scan_sd_element(text: str, start: int) -> tuple[int, str, dict[str, str]]:
    """Scan one ``[SD-ID param="value" ...]`` element beginning at ``text[start]``."""
    i = start + 1
    end_id = i
    while end_id < len(text) and text[end_id] not in " ]":
        end_id += 1
    sd_id = text[i:end_id]
    i = end_id
    params: dict[str, str] = {}
    while i < len(text) and text[i] == " ":
        i += 1
        eq = text.find("=", i)
        if eq == -1 or eq + 1 >= len(text) or text[eq + 1] != '"':
            break
        name = text[i:eq]
        value, i = _read_quoted(text, eq + 2)
        params[name] = value
    if i < len(text) and text[i] == "]":
        i += 1
    return i, sd_id, params


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    """Read a ``"``-terminated PARAM-VALUE starting at ``text[i]`` (after the opening quote)."""
    chars: list[str] = []
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            chars.append(text[i + 1])
            i += 2
            continue
        if char == '"':
            return "".join(chars), i + 1
        chars.append(char)
        i += 1
    return "".join(chars), i


def _parse_rfc3164(
    text: str, envelope: dict[str, Any], header: re.Match[str]
) -> tuple[dict[str, Any], int]:
    """Parse an RFC 3164 header; return ``(envelope, msg_index)``."""
    timestamp_raw = text[header.start(1) : header.end(3)]
    hostname = header.group(4)
    content_start = header.end()

    tag_match = _TAG_RE.match(text, content_start)
    if tag_match is not None:
        tag: str | None = tag_match.group(1)
        procid = tag_match.group(2)
        msg_index = tag_match.end()
    else:
        tag, procid, msg_index = None, None, content_start

    envelope.update(
        format="rfc3164",
        timestamp=timestamp_raw, timestamp_raw=timestamp_raw,
        hostname=hostname,
        tag=tag, app_name=tag, procid=procid,
        header_raw=text[:msg_index],
    )
    return envelope, msg_index
