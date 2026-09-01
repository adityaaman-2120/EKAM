"""Dissect parse engine — delimiter-based positional extraction, no regex.

Modelled on Elastic's ``dissect``. A pattern is a string of ``%{field}``
placeholders; the *literal text between placeholders is the delimiter*::

    "%{ts} %{level}: %{msg}"

The pattern is compiled **once** into a prefix literal plus an ordered list of
``(field, delimiter)`` pairs, and matching is a single left-to-right scan using
only ``str.find`` / ``str.startswith`` — there is no regex engine and **no
backtracking**. That makes dissect several times faster than grok and its cost
independent of the input's shape. Prefer dissect whenever a source's line
structure is fixed; reach for grok only when fields are genuinely optional or
their order varies.

Supported placeholder syntax:

* ``%{field}``   — capture into ``field``.
* ``%{}``        — capture and discard (a skip).
* ``%{+field}``  — append this capture to an earlier ``field`` (joined with
  ``append_separator``, default ``""``).
* ``%{field->}`` — after this field's delimiter, collapse any repeated copies of
  it (padding), e.g. runs of spaces.

Options: ``pattern`` (required), ``append_separator`` (default ``""``).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry

_OPEN = "%{"
_CLOSE = "}"


@dataclass(frozen=True)
class _Field:
    """One compiled placeholder plus the literal delimiter that follows it."""

    name: str
    op: str  # "set" | "skip" | "append"
    delim: str
    right_pad: bool


@dataclass(frozen=True)
class CompiledPattern:
    """A dissect pattern compiled to a prefix literal and ordered fields."""

    prefix: str
    fields: tuple[_Field, ...]


@lru_cache(maxsize=256)
def compile_pattern(pattern: str) -> CompiledPattern:
    """Compile ``pattern`` into a :class:`CompiledPattern` (cached per string)."""
    if _OPEN not in pattern:
        raise ParseError("dissect pattern has no %{...} placeholders", detail={"pattern": pattern})
    prefix = pattern[: pattern.find(_OPEN)]
    specs: list[tuple[str, str, bool]] = []
    delims: list[str] = []
    i = pattern.find(_OPEN)
    while i < len(pattern):
        close = pattern.find(_CLOSE, i + len(_OPEN))
        if close == -1:
            raise ParseError("unterminated %{ in dissect pattern", detail={"pattern": pattern})
        specs.append(_parse_placeholder(pattern[i + len(_OPEN) : close], pattern))
        nxt = pattern.find(_OPEN, close + 1)
        delims.append(pattern[close + 1 : nxt if nxt != -1 else len(pattern)])
        i = nxt if nxt != -1 else len(pattern)

    for index, delim in enumerate(delims[:-1]):
        if delim == "":
            raise ParseError(
                "adjacent dissect placeholders need a delimiter between them",
                detail={"pattern": pattern, "after_field": index},
            )
    fields = tuple(
        _Field(name=name, op=op, delim=delim, right_pad=right_pad)
        for (name, op, right_pad), delim in zip(specs, delims)
    )
    return CompiledPattern(prefix=prefix, fields=fields)


def _parse_placeholder(content: str, pattern: str) -> tuple[str, str, bool]:
    """Return ``(name, op, right_pad)`` for the text inside one ``%{...}``."""
    right_pad = content.endswith("->")
    if right_pad:
        content = content[:-2]
    if content.startswith("+"):
        name = content[1:]
        if not name:
            raise ParseError("%{+} has no field name", detail={"pattern": pattern})
        return name, "append", right_pad
    if content == "":
        return "", "skip", right_pad
    return content, "set", right_pad


@registry.engine
class DissectEngine:
    """Extracts fields from a fixed-structure line via a compiled dissect pattern."""

    name = "dissect"

    def parse(self, text: str, options: dict[str, object]) -> dict[str, str]:
        """Match ``text`` against ``options['pattern']`` and return captured fields."""
        pattern = options.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ParseError("dissect engine requires a non-empty 'pattern' option")
        append_sep = str(options.get("append_separator", ""))
        return _dissect(text, compile_pattern(pattern), append_sep)


def _dissect(text: str, compiled: CompiledPattern, append_sep: str) -> dict[str, str]:
    """Single-pass scan of ``text`` against a compiled pattern."""
    if not text.startswith(compiled.prefix):
        raise ParseError("dissect prefix did not match", detail={"prefix": compiled.prefix})
    pos = len(compiled.prefix)
    out: dict[str, str] = {}
    last = len(compiled.fields) - 1
    for index, field in enumerate(compiled.fields):
        value, pos = (
            _consume_last(text, pos, field)
            if index == last
            else _consume_middle(text, pos, field)
        )
        _apply(out, field, value, append_sep)
    return out


def _consume_middle(text: str, pos: int, field: _Field) -> tuple[str, int]:
    """Capture up to the next occurrence of ``field.delim``; collapse padding if ``->``."""
    end = text.find(field.delim, pos)
    if end == -1:
        raise ParseError(
            "dissect delimiter not found", detail={"delimiter": field.delim, "offset": pos}
        )
    value = text[pos:end]
    pos = end + len(field.delim)
    if field.right_pad:
        while text.startswith(field.delim, pos):
            pos += len(field.delim)
    return value, pos


def _consume_last(text: str, pos: int, field: _Field) -> tuple[str, int]:
    """Capture the remainder; enforce/trim the trailing delimiter if the pattern has one."""
    body = text[pos:]
    if field.delim:
        if not body.endswith(field.delim):
            raise ParseError(
                "dissect trailing delimiter not matched", detail={"delimiter": field.delim}
            )
        if field.right_pad:
            while body.endswith(field.delim):
                body = body[: -len(field.delim)]
        else:
            body = body[: -len(field.delim)]
    return body, len(text)


def _apply(out: dict[str, str], field: _Field, value: str, append_sep: str) -> None:
    """Write ``value`` into ``out`` per the field's operation."""
    if field.op == "skip":
        return
    if field.op == "append":
        prev = out.get(field.name)
        out[field.name] = value if prev is None else f"{prev}{append_sep}{value}"
        return
    out[field.name] = value
