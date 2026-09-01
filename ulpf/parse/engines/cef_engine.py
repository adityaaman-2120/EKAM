"""CEF parse engine — ArcSight Common Event Format.

Layout::

    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

CEF has **two different escaping regimes**, and they must not be mixed up:

* **Header** — fields are separated by ``|``. Only ``\\|`` (literal pipe) and
  ``\\\\`` (literal backslash) are escapes; the split is on *unescaped* pipes.
* **Extension** — ``key=value`` pairs separated by spaces, where values may
  themselves contain spaces. Escapes are ``\\=`` (literal ``=``), ``\\\\``
  (literal backslash), ``\\n`` (newline) and ``\\r`` (carriage return). Pipes in
  the extension are literal — never escaped. Because values contain spaces, the
  extension is scanned for the next *unescaped* ``key=`` boundary rather than
  split on whitespace.

Custom label pairs are expanded: given ``cs1Label=Reason`` and ``cs1=Foo`` the
engine also emits ``Reason=Foo`` while keeping ``cs1`` and ``cs1Label``. This
applies to ``cs1``-``cs6``, ``cn1``-``cn3``, ``cfp1``-``cfp4`` and
``deviceCustomDate1``-``deviceCustomDate2``.
"""

from __future__ import annotations

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry

_HEADER_KEYS = (
    "CEFVersion",
    "deviceVendor",
    "deviceProduct",
    "deviceVersion",
    "deviceEventClassId",
    "name",
    "severity",
)
_CUSTOM_BASES = (
    *(f"cs{i}" for i in range(1, 7)),
    *(f"cn{i}" for i in range(1, 4)),
    *(f"cfp{i}" for i in range(1, 5)),
    *(f"deviceCustomDate{i}" for i in range(1, 3)),
)
_HEADER_ESCAPES = "|\\"
_EXT_ESCAPES = {"\\": "\\", "=": "=", "n": "\n", "r": "\r"}


@registry.engine
class CefEngine:
    """Parses a CEF line into a flat dict of header fields plus extension keys."""

    name = "cef"

    def parse(self, text: str, options: dict[str, object]) -> dict[str, str]:
        """Parse ``text`` (which must contain a ``CEF:`` marker) into flat fields."""
        marker = text.find("CEF:")
        if marker == -1:
            raise ParseError("no 'CEF:' marker found in line")
        segments = _split_unescaped_pipes(text[marker + 4 :], maxsplit=7)
        if len(segments) < 7:
            raise ParseError("CEF header has fewer than 7 fields", detail={"found": len(segments)})

        fields: dict[str, str] = {
            key: _unescape_header(value) for key, value in zip(_HEADER_KEYS, segments[:7])
        }
        if len(segments) > 7:
            fields.update(_parse_extension(segments[7]))
        _expand_custom_labels(fields)
        return fields


def _split_unescaped_pipes(text: str, maxsplit: int) -> list[str]:
    """Split on unescaped ``|`` (up to ``maxsplit`` times); escape pairs stay intact."""
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
    """Resolve the header escapes ``\\|`` and ``\\\\`` only."""
    out: list[str] = []
    i, n = 0, len(field)
    while i < n:
        if field[i] == "\\" and i + 1 < n and field[i + 1] in _HEADER_ESCAPES:
            out.append(field[i + 1])
            i += 2
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def _parse_extension(ext: str) -> dict[str, str]:
    """Scan the extension into ``{key: value}``, respecting spaces inside values."""
    fields: dict[str, str] = {}
    i, n = 0, len(ext)
    while i < n:
        while i < n and ext[i] == " ":
            i += 1
        if i >= n:
            break
        key_start = i
        while i < n and ext[i] not in "= ":
            i += 1
        if i >= n or ext[i] == " ":
            continue  # token with no '=' -> not a pair
        key = ext[key_start:i]
        i += 1  # past '='
        end = _find_value_end(ext, i)
        if key:
            fields[key] = _unescape_extension(ext[i:end])
        i = end
    return fields


def _find_value_end(ext: str, start: int) -> int:
    """Index where the value beginning at ``start`` ends (next unescaped ``key=``)."""
    i, n = start, len(ext)
    while i < n:
        char = ext[i]
        if char == "\\" and i + 1 < n and ext[i + 1] in _EXT_ESCAPES:
            i += 2
            continue
        if char == " " and _looks_like_key_eq(ext, i + 1):
            return i
        i += 1
    return n


def _looks_like_key_eq(ext: str, pos: int) -> bool:
    """Whether ``ext[pos:]`` starts with ``<non-space/non-=/non-backslash chars>=``."""
    j, n = pos, len(ext)
    while j < n and ext[j] not in "= \\":
        j += 1
    return j > pos and j < n and ext[j] == "="


def _unescape_extension(value: str) -> str:
    """Resolve the extension escapes ``\\=``, ``\\\\``, ``\\n`` and ``\\r``."""
    out: list[str] = []
    i, n = 0, len(value)
    while i < n:
        if value[i] == "\\" and i + 1 < n and value[i + 1] in _EXT_ESCAPES:
            out.append(_EXT_ESCAPES[value[i + 1]])
            i += 2
        else:
            out.append(value[i])
            i += 1
    return "".join(out)


def _expand_custom_labels(fields: dict[str, str]) -> None:
    """Emit ``<label>=<value>`` for each present ``csN``/``csNLabel`` style pair."""
    for base in _CUSTOM_BASES:
        label_key = f"{base}Label"
        if base in fields and label_key in fields:
            label = fields[label_key].strip()
            if label and label not in (base, label_key):
                fields[label] = fields[base]
