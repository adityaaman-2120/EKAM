"""Key=value parse engine (FortiGate and similar ``k=v k="v v" ...`` logs).

The scanner walks the line key by key. For each key it reads up to
``kv_separator``; the value is then either a double-quoted run (which may contain
spaces *and* the pair separator *and* the kv separator) read to its closing
quote, or an unquoted run that ends at the next ``pair_separator``. It never
splits naively on whitespace, so ``msg="src=1.2.3.4 dst=5.6.7.8"`` yields one
field, not four.

Options:

* ``pair_separator`` — between pairs (default ``" "``); runs of it are skipped.
* ``kv_separator``   — between key and value (default ``"="``).
* ``strip_quotes``   — remove the surrounding quotes from quoted values
  (default ``True``).

All values are returned as strings — ``k=v`` text carries no type information;
coercion is the normalizer's job. Tokens with no ``kv_separator`` before the
next ``pair_separator`` are skipped.
"""

from __future__ import annotations

from typing import Any

from ulpf.core.errors import ParseError
from ulpf.parse.registry import registry


@registry.engine
class KvEngine:
    """Parses ``key=value`` lines with quote-aware value scanning."""

    name = "kv"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Scan ``text`` into a flat ``{str: str}`` dict of key/value pairs."""
        pair_sep = options.get("pair_separator", " ")
        kv_sep = options.get("kv_separator", "=")
        strip_quotes = bool(options.get("strip_quotes", True))
        if not pair_sep or not kv_sep:
            raise ParseError(
                "pair_separator and kv_separator must be non-empty",
                detail={"pair_separator": pair_sep, "kv_separator": kv_sep},
            )
        return _scan(text.strip(), pair_sep, kv_sep, strip_quotes)


def _scan(text: str, pair_sep: str, kv_sep: str, strip_quotes: bool) -> dict[str, str]:
    """Walk ``text`` key by key, returning the extracted pairs."""
    fields: dict[str, str] = {}
    i, n = 0, len(text)
    while i < n:
        while text.startswith(pair_sep, i):
            i += len(pair_sep)
        if i >= n:
            break
        eq = text.find(kv_sep, i)
        if eq == -1:
            break
        next_sep = text.find(pair_sep, i)
        if next_sep != -1 and next_sep < eq:
            i = next_sep + len(pair_sep)  # bare token with no kv_separator; skip
            continue
        key = text[i:eq]
        i = eq + len(kv_sep)
        if i < n and text[i] == '"':
            value, i = _read_quoted(text, i + 1)
            if not strip_quotes:
                value = f'"{value}"'
        else:
            end = text.find(pair_sep, i)
            end = n if end == -1 else end
            value, i = text[i:end], end
        fields[key] = value
    return fields


def _read_quoted(text: str, i: int) -> tuple[str, int]:
    """Read a ``"``-terminated value starting at ``text[i]`` (after the open quote)."""
    chars: list[str] = []
    n = len(text)
    while i < n:
        char = text[i]
        if char == "\\" and i + 1 < n:
            chars.append(text[i + 1])
            i += 2
            continue
        if char == '"':
            return "".join(chars), i + 1
        chars.append(char)
        i += 1
    return "".join(chars), i  # unterminated quote: take the remainder
