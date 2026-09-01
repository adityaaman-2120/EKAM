"""Cheap, ordered log-format detection.

``sniff(line)`` runs a short list of checks, cheapest and most discriminating
first, and returns one of ``syslog``, ``cef``, ``leef``, ``json``, ``kv``,
``tsv``, ``csv``, ``unknown``.

Syslog is checked **first** because a syslog header routinely *wraps* a CEF,
LEEF, or JSON payload (``<134>... CEF:0|...``). ``sniff_layered(line)`` returns
``(outer_format, inner_format)``: it sniffs the line, and if the outer format is
syslog it strips the envelope and sniffs the remainder; otherwise the inner
format simply equals the outer.

:class:`Sniffer` adds a bounded LRU cache keyed on ``source_id`` so a source is
classified once rather than per line. Pass ``cache_bypass=True`` to force a fresh
detection (e.g. when a source's format is known to have changed). The cache is
instance state — no module-level mutable state.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict

from ulpf.parse.syslog_envelope import parse_syslog_envelope

Format = str  # one of the literals documented above

_HEAD = 200
_SYSLOG_PRI_RE = re.compile(r"^<\d+>")
_KEY_EQ_RE = re.compile(r"[^\s=]+=")


def sniff(line: str) -> Format:
    """Classify one log line. See module docstring for the ordered checks."""
    if _SYSLOG_PRI_RE.match(line):
        return "syslog"
    head = line[:_HEAD]
    if "CEF:" in head:
        return "cef"
    if "LEEF:" in head:
        return "leef"
    if line.startswith(("{", "[")) and _is_json(line):
        return "json"
    if line.count("\t") >= 3:
        return "tsv"
    if len(_KEY_EQ_RE.findall(line)) >= 3:
        return "kv"
    if line.count(",") >= 8:
        return "csv"
    return "unknown"


def sniff_layered(line: str) -> tuple[Format, Format]:
    """Return ``(outer_format, inner_format)``, unwrapping a syslog envelope once."""
    outer = sniff(line)
    if outer != "syslog":
        return outer, outer
    envelope, message = parse_syslog_envelope(line.encode("utf-8", "replace"))
    payload = message.decode("utf-8", "replace")
    inner = sniff(payload)
    # RFC 3164 tag parsing greedily eats a leading ``CEF:``/``LEEF:`` marker as
    # the syslog tag; if the bare payload looks like nothing, retry with the tag
    # glued back on so a syslog-wrapped CEF/LEEF is still recognised.
    tag = envelope.get("tag")
    if inner == "unknown" and isinstance(tag, str) and tag:
        inner = sniff(f"{tag}:{payload}")
    return outer, inner


def _is_json(text: str) -> bool:
    """Whether ``text`` parses as a single JSON document."""
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


class Sniffer:
    """Format detection with a per-``source_id`` LRU cache."""

    def __init__(self, maxsize: int = 1024) -> None:
        """Create a sniffer whose cache holds at most ``maxsize`` sources."""
        self._maxsize = maxsize
        self._cache: OrderedDict[str, tuple[Format, Format]] = OrderedDict()

    def sniff_source(self, source_id: str, line: str, *, cache_bypass: bool = False) -> Format:
        """Return the flat format for ``source_id``, sniffing ``line`` only on a cache miss."""
        return self.sniff_source_layered(source_id, line, cache_bypass=cache_bypass)[0]

    def sniff_source_layered(
        self, source_id: str, line: str, *, cache_bypass: bool = False
    ) -> tuple[Format, Format]:
        """Like :func:`sniff_layered`, cached per ``source_id`` unless ``cache_bypass``."""
        if cache_bypass:
            return sniff_layered(line)
        cached = self._cache.get(source_id)
        if cached is not None:
            self._cache.move_to_end(source_id)
            return cached
        result = sniff_layered(line)
        self._cache[source_id] = result
        self._cache.move_to_end(source_id)
        if len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)
        return result

    def clear(self) -> None:
        """Drop every cached classification."""
        self._cache.clear()
