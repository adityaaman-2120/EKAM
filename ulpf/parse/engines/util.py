"""Shared helpers for parse engines.

:func:`flatten` collapses an arbitrarily nested dict/list structure into the flat
``{str: scalar}`` shape every engine must return: nested dict keys are joined
with ``sep`` (``.`` by default), and a list index is joined the same way
(``tags.0``, ``users.1.name``).
"""

from __future__ import annotations

from typing import Any


def flatten(obj: Any, prefix: str = "", *, sep: str = ".") -> dict[str, Any]:
    """Flatten nested dicts/lists to a single-level dict with dotted keys.

    Args:
        obj: The value to flatten (typically a dict).
        prefix: Key prefix applied to every produced key.
        sep: Separator placed between path segments and before list indices.

    Returns:
        A flat dict. Scalars pass through unchanged. An **empty** dict or list is
        kept as-is under its key (nothing to descend into). Flattening a bare
        scalar or empty container yields ``{prefix: obj}`` (``prefix`` may be "").

    Note:
        If a real key already contains ``sep``, it can collide with a flattened
        path (``{"a.b": 1}`` vs ``{"a": {"b": 2}}``); the last write wins.
    """
    out: dict[str, Any] = {}
    _flatten_into(obj, prefix, sep, out)
    return out


def _flatten_into(obj: Any, prefix: str, sep: str, out: dict[str, Any]) -> None:
    """Recursively write flattened entries for ``obj`` into ``out``."""
    if isinstance(obj, dict):
        if not obj:
            out[prefix] = {}
            return
        for key, value in obj.items():
            child = f"{prefix}{sep}{key}" if prefix else str(key)
            _flatten_into(value, child, sep, out)
    elif isinstance(obj, (list, tuple)):
        if not obj:
            out[prefix] = []
            return
        for index, value in enumerate(obj):
            child = f"{prefix}{sep}{index}" if prefix else str(index)
            _flatten_into(value, child, sep, out)
    else:
        out[prefix] = obj
