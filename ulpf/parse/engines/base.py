"""The parse-engine contract.

A parse engine turns the source-specific *body* of a log line (after the syslog
envelope has been stripped) into extracted fields. Every engine MUST return a
**flat** ``dict`` mapping string keys to scalar values — no nested dicts or
lists. Nested structure is expressed with dotted keys, and a list index becomes
part of the key (see :func:`ulpf.parse.engines.util.flatten`, which every engine
should use for this).

Keeping the output flat means the normalizer, the Parquet writer, and the
columnar stores all see one predictable shape regardless of source.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ParseEngine(Protocol):
    """Extracts flat fields from a source-specific message body."""

    name: str

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Parse ``text`` into a flat ``{str: scalar}`` dict.

        Args:
            text: The message body to parse (syslog envelope already removed).
            options: Per-source configuration for this engine (delimiters,
                field names, grok patterns, ...). Never mutated.

        Returns:
            A flat dict: string keys, scalar values, nested paths dotted.
        """
        ...
