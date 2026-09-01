"""TSV parse engine — Zeek (Bro) TSV log mode.

Zeek TSV streams carry their own schema inline via ``#``-directive lines:

* ``#separator \\x09`` — the field separator (usually TAB, written as an escape).
* ``#set_separator``, ``#empty_field``, ``#unset_field`` — the in-set delimiter
  and the two sentinel strings.
* ``#fields`` — the ordered column names for this stream.
* ``#types``  — the Zeek type of each column; ``set[...]`` / ``vector[...]`` /
  ``table[...]`` columns are split on the set separator into a list.

Any line starting with ``#`` is metadata and yields **no event** (an empty
dict). A data line is mapped positionally onto the remembered ``#fields``.
Column state is kept per *stream* — pass ``options["stream"]`` (or
``"source_id"``) so several interleaved Zeek logs on one engine instance don't
clobber each other's schema.

Options: ``columns`` (explicit override), ``separator``, ``set_separator``
(default ``,``), ``unset_field`` (default ``-`` -> ``None``), ``empty_field``
(default ``(empty)`` -> ``None`` for a scalar, ``[]`` for a set), ``list_fields``
(names to treat as set/vector even without a ``#types`` line).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry

_LIST_TYPE_PREFIXES = ("set[", "vector[", "table[")


@dataclass
class _Stream:
    """Remembered schema for one Zeek TSV stream."""

    columns: list[str] | None = None
    type_tokens: list[str] | None = None
    list_cols: set[str] = field(default_factory=set)
    separator: str = "\t"
    set_separator: str = ","
    unset_field: str = "-"
    empty_field: str = "(empty)"


@registry.engine
class TsvEngine:
    """Parses Zeek TSV: consumes ``#`` directives, maps data rows onto ``#fields``."""

    name = "tsv"

    def __init__(self) -> None:
        """Set up per-stream schema memory."""
        self._streams: dict[str, _Stream] = {}

    def parse(self, text: str, options: dict[str, object]) -> dict[str, object]:
        """Parse one line: a ``#`` directive updates state and returns ``{}``."""
        stream_key = str(options.get("stream") or options.get("source_id") or "")
        stream = self._streams.setdefault(stream_key, _Stream())
        line = text.rstrip("\r\n")
        if line.startswith("#"):
            _apply_directive(stream, line)
            return {}
        return _parse_data_line(line, stream, options)


def _parse_data_line(line: str, stream: _Stream, options: dict[str, object]) -> dict[str, object]:
    """Map a data row onto the effective column list, coercing sentinels and sets."""
    columns = options.get("columns") or stream.columns
    if not columns:
        raise ParseError("tsv engine: no #fields header seen and no 'columns' option")
    separator = str(options.get("separator") or stream.separator)
    unset = str(options.get("unset_field", stream.unset_field))
    empty = str(options.get("empty_field", stream.empty_field))
    set_sep = str(options.get("set_separator") or stream.set_separator)
    list_cols = set(stream.list_cols) | set(options.get("list_fields") or ())  # type: ignore[arg-type]

    values = line.split(separator)
    result: dict[str, object] = {}
    for index, name in enumerate(columns):
        if index >= len(values):
            break
        result[name] = _coerce(values[index], name in list_cols, unset, empty, set_sep)
    for index in range(len(columns), len(values)):
        result[f"_extra.{index}"] = _coerce(values[index], False, unset, empty, set_sep)
    return result


def _coerce(
    raw: str, is_list: bool, unset: str, empty: str, set_sep: str
) -> str | None | list[str | None]:
    """Apply Zeek's unset/empty sentinels and set-splitting to one raw field."""
    if raw == unset:
        return None
    if is_list:
        if raw == empty:
            return []
        return [None if part == unset else part for part in raw.split(set_sep)]
    if raw == empty:
        return None
    return raw


def _apply_directive(stream: _Stream, line: str) -> None:
    """Update ``stream`` state from a ``#`` directive line."""
    if line.startswith("#separator"):
        value = line[len("#separator") :].strip()
        if value:
            stream.separator = _decode_separator(value)
        return
    name, _, value = line.partition(stream.separator)
    directive = name.lstrip("#")
    if directive == "set_separator":
        stream.set_separator = value or stream.set_separator
    elif directive == "empty_field":
        stream.empty_field = value or stream.empty_field
    elif directive == "unset_field":
        stream.unset_field = value or stream.unset_field
    elif directive == "fields":
        stream.columns = value.split(stream.separator) if value else None
        _reconcile_list_cols(stream)
    elif directive == "types":
        stream.type_tokens = value.split(stream.separator) if value else None
        _reconcile_list_cols(stream)


def _reconcile_list_cols(stream: _Stream) -> None:
    """Recompute which columns are set/vector types from ``#fields`` + ``#types``."""
    if not stream.columns or not stream.type_tokens:
        return
    if len(stream.columns) != len(stream.type_tokens):
        raise ParseError(
            "Zeek #fields and #types column counts differ",
            detail={
                "fields": len(stream.columns),
                "types": len(stream.type_tokens),
            },
        )
    stream.list_cols = {
        name
        for name, type_token in zip(stream.columns, stream.type_tokens, strict=True)
        if type_token.startswith(_LIST_TYPE_PREFIXES)
    }


def _decode_separator(token: str) -> str:
    """Decode a ``#separator`` value: ``\\x09`` / ``0x09`` / ``\\t`` -> TAB, else literal."""
    lowered = token.lower()
    if lowered in ("\\t", "\\x09", "0x09"):
        return "\t"
    if lowered[:2] in ("\\x", "0x") and len(token) == 4:
        return chr(int(token[2:], 16))
    return token
