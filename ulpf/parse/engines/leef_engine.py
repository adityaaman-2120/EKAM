"""LEEF parse engine — IBM QRadar Log Event Extended Format, 1.0 and 2.0.

Header (pipe-delimited, ``\\|`` / ``\\\\`` escapes)::

    LEEF:1.0|Vendor|Product|Version|EventID|<TAB-separated key=value pairs>
    LEEF:2.0|Vendor|Product|Version|EventID|<delim>|<pairs separated by <delim>>

The version is read from the header and drives everything else:

* **1.0** — attributes are separated by a literal TAB.
* **2.0** — the 6th header field *names* the attribute delimiter. It is either a
  single literal character (``^``, ``|`` ...) or a hex code — ``0x09`` or
  ``x09`` — which resolves to that byte (``0x09`` -> TAB). An empty delimiter
  field falls back to TAB.

An optional syslog header in front of ``LEEF:`` is tolerated — parsing starts at
the marker.
"""

from __future__ import annotations

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry

_HEADER_KEYS = ("leefVersion", "vendor", "product", "productVersion", "eventId")
_HEX_DIGITS = frozenset("0123456789abcdef")


@registry.engine
class LeefEngine:
    """Parses a LEEF 1.0 or 2.0 line into flat header + attribute fields."""

    name = "leef"

    def parse(self, text: str, options: dict[str, object]) -> dict[str, str]:
        """Parse ``text`` (which must contain a ``LEEF:`` marker) into flat fields."""
        marker = text.rstrip("\r\n").find("LEEF:")
        if marker == -1:
            raise ParseError("no 'LEEF:' marker found in line")
        rest = text.rstrip("\r\n")[marker + len("LEEF:") :]
        version = rest.split("|", 1)[0].strip()
        if version.startswith("1"):
            return _parse_v1(rest)
        if version.startswith("2"):
            return _parse_v2(rest)
        raise ParseError("unsupported LEEF version", detail={"version": version})


def _parse_v1(rest: str) -> dict[str, str]:
    """Parse a LEEF 1.0 body (attributes are TAB-separated)."""
    parts = _split_header_pipes(rest, maxsplit=5)
    if len(parts) < 5:
        raise ParseError("LEEF 1.0 header is incomplete", detail={"found": len(parts)})
    fields = {
        key: _unescape_header(value)
        for key, value in zip(_HEADER_KEYS, parts[:5], strict=True)
    }
    fields.update(_parse_attributes(parts[5] if len(parts) > 5 else "", "\t"))
    return fields


def _parse_v2(rest: str) -> dict[str, str]:
    """Parse a LEEF 2.0 body (6th field names the attribute delimiter)."""
    parts = _split_header_pipes(rest, maxsplit=6)
    if len(parts) < 6:
        raise ParseError("LEEF 2.0 header is incomplete", detail={"found": len(parts)})
    fields = {
        key: _unescape_header(value)
        for key, value in zip(_HEADER_KEYS, parts[:5], strict=True)
    }
    delimiter_raw = _unescape_header(parts[5])
    fields["delimiter"] = delimiter_raw
    fields.update(
        _parse_attributes(
            parts[6] if len(parts) > 6 else "", _resolve_delimiter(delimiter_raw)
        )
    )
    return fields


def _resolve_delimiter(raw: str) -> str:
    """Resolve a LEEF 2.0 delimiter field: literal char, ``0x09``/``x09`` hex, or empty->TAB."""
    if raw == "":
        return "\t"
    lowered = raw.lower()
    hex_part: str | None = None
    if lowered.startswith("0x"):
        hex_part = lowered[2:]
    elif lowered.startswith("x") and len(lowered) > 1:
        hex_part = lowered[1:]
    if hex_part is not None:
        if 1 <= len(hex_part) <= 2 and all(char in _HEX_DIGITS for char in hex_part):
            return chr(int(hex_part, 16))
        raise ParseError("invalid LEEF 2.0 hex delimiter", detail={"delimiter": raw})
    if len(raw) == 1:
        return raw
    raise ParseError("invalid LEEF 2.0 delimiter", detail={"delimiter": raw})


def _parse_attributes(body: str, delimiter: str) -> dict[str, str]:
    """Split ``body`` on ``delimiter`` into ``{key: value}`` (value split on first ``=``)."""
    fields: dict[str, str] = {}
    if not body:
        return fields
    for piece in body.split(delimiter):
        if "=" not in piece:
            continue
        key, _, value = piece.partition("=")
        key = key.strip()
        if key:
            fields[key] = value
    return fields


def _split_header_pipes(text: str, maxsplit: int) -> list[str]:
    """Split on unescaped ``|`` up to ``maxsplit`` times; ``\\x`` pairs stay intact."""
    parts: list[str] = []
    buf: list[str] = []
    i, n, done = 0, len(text), 0
    while i < n:
        char = text[i]
        if char == "\\" and i + 1 < n:
            buf.append(char)
            buf.append(text[i + 1])
            i += 2
            continue
        if char == "|" and done < maxsplit:
            parts.append("".join(buf))
            buf = []
            done += 1
            i += 1
            continue
        buf.append(char)
        i += 1
    parts.append("".join(buf))
    return parts


def _unescape_header(field: str) -> str:
    """Resolve the header escapes ``\\|`` and ``\\\\``."""
    out: list[str] = []
    i, n = 0, len(field)
    while i < n:
        if field[i] == "\\" and i + 1 < n and field[i + 1] in "|\\":
            out.append(field[i + 1])
            i += 2
        else:
            out.append(field[i])
            i += 1
    return "".join(out)
