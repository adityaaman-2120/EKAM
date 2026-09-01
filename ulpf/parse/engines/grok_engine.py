"""Grok parse engine — the LAST resort.

Grok compiles ``%{PATTERN:field}`` templates into a regular expression, so it
inherits backtracking regex engines' worst-case behaviour: **catastrophic
backtracking**. A pattern like ``(a+)+b`` matched against ``"aaaaaaaaaaaaaa!"``
(no trailing ``b``) forces the engine to try an exponential number of ways to
split the ``a`` run across the inner and outer ``+`` before giving up — the
match time roughly doubles with every extra character, so a handful of extra
bytes can turn a sub-millisecond parse into one that would run for hours,
hanging whatever worker is running it.

Prefer, in order: :mod:`~ulpf.parse.engines.json_engine`,
:mod:`~ulpf.parse.engines.kv_engine`, :mod:`~ulpf.parse.engines.csv_engine`,
:mod:`~ulpf.parse.engines.dissect_engine`. Reach for grok only when none of
those fit — free-text log lines with a fixed-ish but not fully positional
shape. Two mitigations make that survivable:

* Every match runs under a hard **timeout** (``grok_timeout_ms``, from
  ``ParseSettings.grok_timeout_ms``). On timeout this engine raises
  :class:`~ulpf.core.errors.ParseError` with ``detail["reason"] ==
  "grok_timeout"`` so the event is dead-lettered — visibly, with the raw bytes
  intact — instead of the worker hanging.
* :func:`lint_pattern` flags the two classic danger signs — nested quantifiers
  (``(x+)+``) and an unanchored leading greedy match (``.*...``) — so a bad
  pattern can be caught at onboarding time, before it ever sees traffic.

Patterns are compiled once (cached per ``(pattern, extra_patterns)``) using the
``regex`` module, which (unlike :mod:`re`) supports a per-match ``timeout=``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import regex

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry

_log = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).resolve().parent.parent / "patterns"
_BASE_GROK_FILE = _PATTERNS_DIR / "base.grok"
_MAX_NESTING_DEPTH = 20
_DEFAULT_TIMEOUT_MS = 100

_NESTED_QUANTIFIER_RE = regex.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
_QUANTIFIED_REF_RE = regex.compile(r"%\{[A-Za-z0-9_]+(?::[^}]*)?\}[+*]")
_LEADING_GREEDY = (".*", ".+", "%{GREEDYDATA}", "%{GREEDYDATA:", "%{DATA}", "%{DATA:")


def load_pattern_file(path: Path) -> dict[str, str]:
    """Load a grok pattern library file (``NAME <space> regex`` per line)."""
    patterns: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            patterns[parts[0]] = parts[1]
    return patterns


def lint_pattern(pattern: str) -> list[str]:
    """Return human-readable warnings about likely-pathological constructs.

    Flags nested quantifiers (``(x+)+``, ``(x*)*``, a quantified ``%{REF}+``)
    and an unanchored leading greedy match (``.*``/``.+``/``GREEDYDATA``/``DATA``
    at the very start of the pattern) — the two classic causes of catastrophic
    backtracking. An empty list means no warnings were found (not a guarantee
    of safety).
    """
    warnings: list[str] = []
    for match in _NESTED_QUANTIFIER_RE.finditer(pattern):
        warnings.append(f"nested quantifier near {match.group(0)!r} risks catastrophic backtracking")
    for match in _QUANTIFIED_REF_RE.finditer(pattern):
        warnings.append(f"quantified grok reference {match.group(0)!r} risks runaway matching")
    if pattern.startswith(_LEADING_GREEDY):
        warnings.append("pattern starts with an unanchored greedy match; anchor with ^ or a literal")
    return warnings


@dataclass(frozen=True)
class _CompiledGrok:
    """A compiled grok pattern plus the map back from regex group to field name."""

    matcher: regex.Pattern[str]
    group_to_field: dict[str, str] = field(default_factory=dict)


class _Compiler:
    """Expands ``%{NAME:field}`` references into a single regex source string."""

    def __init__(self, library: dict[str, str]) -> None:
        self._library = library
        self._seen: dict[str, int] = {}
        self.group_to_field: dict[str, str] = {}

    def compile(self, grok: str, depth: int = 0) -> str:
        """Recursively expand ``grok`` into plain regex source."""
        if depth > _MAX_NESTING_DEPTH:
            raise ParseError("grok pattern nesting exceeded", detail={"max_depth": _MAX_NESTING_DEPTH})
        out: list[str] = []
        i = 0
        while True:
            start = grok.find("%{", i)
            if start == -1:
                out.append(grok[i:])
                return "".join(out)
            out.append(grok[i:start])
            end = grok.find("}", start + 2)
            if end == -1:
                raise ParseError("unterminated %{ in grok pattern", detail={"pattern": grok})
            out.append(self._expand(grok[start + 2 : end], depth))
            i = end + 1

    def _expand(self, content: str, depth: int) -> str:
        """Expand one ``NAME``, ``NAME:field``, or ``NAME:field:type`` reference."""
        name, _, rest = content.partition(":")
        field_name = rest.partition(":")[0]  # drop an optional trailing :type hint
        if name not in self._library:
            raise ParseError("unknown grok pattern reference", detail={"name": name})
        inner = self.compile(self._library[name], depth + 1)
        if not field_name:
            return f"(?:{inner})"
        group = self._unique_group(field_name)
        self.group_to_field[group] = field_name
        return f"(?P<{group}>{inner})"

    def _unique_group(self, field_name: str) -> str:
        """A regex-safe, collision-free internal group name for ``field_name``."""
        base = regex.sub(r"\W", "_", field_name)
        if not base or base[0].isdigit():
            base = f"f_{base}"
        self._seen[base] = self._seen.get(base, 0) + 1
        count = self._seen[base]
        return base if count == 1 else f"{base}__{count}"


@registry.engine
class GrokEngine:
    """Matches a fixed-ish log line against a compiled, timeout-guarded grok pattern."""

    name = "grok"

    def __init__(self) -> None:
        """Load the base pattern library and set up the per-instance compile cache."""
        self._library = load_pattern_file(_BASE_GROK_FILE)
        self._cache: dict[object, _CompiledGrok] = {}

    def parse(self, text: str, options: dict[str, object]) -> dict[str, str]:
        """Match ``text`` against ``options['pattern']`` within a hard timeout."""
        grok_pattern = options.get("pattern")
        if not isinstance(grok_pattern, str) or not grok_pattern:
            raise ParseError("grok engine requires a non-empty 'pattern' option")
        extra = dict(options.get("patterns") or {})  # type: ignore[arg-type]
        timeout_ms = int(options.get("grok_timeout_ms", _DEFAULT_TIMEOUT_MS))  # type: ignore[arg-type]

        compiled = self._get_compiled(grok_pattern, extra)
        try:
            match = compiled.matcher.search(text, timeout=timeout_ms / 1000.0)
        except TimeoutError as exc:
            raise ParseError(
                "grok match timed out",
                detail={"reason": "grok_timeout", "timeout_ms": timeout_ms, "pattern": grok_pattern},
            ) from exc
        if match is None:
            raise ParseError(
                "grok pattern did not match", detail={"reason": "grok_no_match", "pattern": grok_pattern}
            )
        return {
            compiled.group_to_field[group]: value
            for group, value in match.groupdict().items()
            if value is not None
        }

    def _get_compiled(self, grok_pattern: str, extra: dict[str, str]) -> _CompiledGrok:
        """Compile ``grok_pattern`` (with any ``extra`` patterns), caching the result."""
        key: object = grok_pattern if not extra else (grok_pattern, tuple(sorted(extra.items())))
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        for warning in lint_pattern(grok_pattern):
            _log.warning("grok lint: %s", warning, extra={"pattern": grok_pattern})

        compiler = _Compiler({**self._library, **extra})
        source = compiler.compile(grok_pattern)
        try:
            matcher = regex.compile(source)
        except regex.error as exc:
            raise ParseError("grok pattern failed to compile", detail={"error": str(exc)}) from exc

        result = _CompiledGrok(matcher=matcher, group_to_field=compiler.group_to_field)
        self._cache[key] = result
        return result
