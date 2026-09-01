"""JSON parse engine (Zeek/Suricata JSON, generic app JSON).

Loads the body with ``orjson`` and flattens it to dotted keys via
:func:`ulpf.parse.engines.util.flatten`. Scalar types are preserved exactly —
ints stay ints, floats stay floats, bools stay bools, ``null`` stays ``None`` —
nothing is stringified.

Options:

* ``array_mode`` — ``"flatten"`` (default): each list element gets its index in
  the key (``alert.metadata.created_at.0``). ``"join"``: a list whose elements
  are all scalars becomes a single comma-joined string; lists that contain
  objects or nested lists still fall back to index keys.
* ``sep`` — key separator, default ``"."``.

A top-level JSON object is parsed directly. A top-level array of exactly one
object is unwrapped; any other array (or a top-level scalar) raises
:class:`~ulpf.core.errors.ParseError`.
"""

from __future__ import annotations

from typing import Any

import orjson

from ulpf.core.errors import ParseError
from ulpf.parse.engines.util import flatten
from ulpf.parse.registry import registry

_ARRAY_MODES = ("flatten", "join")


@registry.engine
class JsonEngine:
    """Parses a JSON document into a flat, dotted, type-preserving dict."""

    name = "json"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Parse ``text`` (a JSON document) into a flat dict."""
        try:
            loaded = orjson.loads(text)
        except orjson.JSONDecodeError as exc:
            raise ParseError("invalid JSON", detail={"error": str(exc)}) from exc

        array_mode = options.get("array_mode", "flatten")
        if array_mode not in _ARRAY_MODES:
            raise ParseError("unknown array_mode", detail={"array_mode": array_mode})

        obj = _as_object(loaded)
        prepared = _prepare(obj, array_mode)
        return flatten(prepared, sep=options.get("sep", "."))


def _as_object(loaded: Any) -> dict[str, Any]:
    """Return a dict from a parsed JSON value, or raise a clear ``ParseError``."""
    if isinstance(loaded, dict):
        return loaded
    if isinstance(loaded, list):
        if len(loaded) == 1 and isinstance(loaded[0], dict):
            return loaded[0]
        raise ParseError(
            "expected a JSON object; got a top-level array",
            detail={"length": len(loaded)},
        )
    raise ParseError(
        "expected a JSON object at the top level",
        detail={"type": type(loaded).__name__},
    )


def _prepare(value: Any, array_mode: str) -> Any:
    """Apply ``array_mode`` to lists, recursively, before flattening."""
    if isinstance(value, dict):
        return {key: _prepare(item, array_mode) for key, item in value.items()}
    if isinstance(value, list):
        if array_mode == "join" and all(not isinstance(e, (dict, list)) for e in value):
            return ",".join(_scalar_str(e) for e in value)
        return [_prepare(item, array_mode) for item in value]
    return value


def _scalar_str(value: Any) -> str:
    """JSON-flavoured string form of a scalar for ``array_mode="join"``."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)
