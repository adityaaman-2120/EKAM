"""Positional CSV parse engine (PAN-OS and similar headerless CSV logs).

The row is split with the standard :mod:`csv` reader (so quoting and embedded
delimiters are handled) and mapped onto an ordered ``columns`` list by position.

Options:

* ``columns``    — ordered list of field names.
* ``column_map`` — ``{"product": ..., "version": ...}`` resolved against
  :data:`ulpf.parse.column_maps.COLUMN_MAPS` (used when ``columns`` is absent).
  This is the version-keyed path for PAN-OS-style logs whose field *order*
  changes between releases. One of ``columns`` / ``column_map`` is required.
* ``delimiter``  — single character, default ``","``.
* ``quotechar``  — single character, default ``'"'``.
* ``skip_empty`` — map empty fields to ``None`` (default ``True``).

Nothing is lost when the row width does not match the map:

* **more** columns than names -> the extras are kept under ``_extra.<index>``.
* **fewer** columns than names -> the missing names are simply absent and
  ``_truncated`` is set to ``True``.
"""

from __future__ import annotations

import csv
from typing import Any

from ulpf.core.errors import ParseError
from ulpf.parse.column_maps import get_column_map
from ulpf.parse.registry import registry


@registry.engine
class CsvEngine:
    """Maps a delimited row onto an ordered list of column names."""

    name = "csv"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Split ``text`` and map it positionally onto the resolved column list."""
        columns = options.get("columns") or _resolve_column_map(options.get("column_map"))
        if not columns:
            raise ParseError(
                "csv engine requires a 'columns' list or a resolvable 'column_map' option"
            )
        delimiter = options.get("delimiter", ",")
        quotechar = options.get("quotechar", '"')
        skip_empty = bool(options.get("skip_empty", True))
        if len(delimiter) != 1:
            raise ParseError(
                "delimiter must be a single character", detail={"delimiter": delimiter}
            )

        row = _read_row(text, delimiter, quotechar)
        return _map_row(row, [str(name) for name in columns], skip_empty)


def _resolve_column_map(spec: Any) -> list[str] | None:
    """Resolve a ``{"product", "version"}`` mapping to an ordered column list."""
    if not isinstance(spec, dict):
        return None
    product, version = spec.get("product"), spec.get("version")
    if not product or version is None:
        return None
    try:
        return get_column_map(str(product), str(version))
    except KeyError as exc:
        raise ParseError("unknown column_map", detail={"column_map": spec}) from exc


def _read_row(text: str, delimiter: str, quotechar: str) -> list[str]:
    """Parse a single CSV record from ``text``."""
    reader = csv.reader([text], delimiter=delimiter, quotechar=quotechar)
    try:
        return next(reader)
    except StopIteration:
        return []
    except csv.Error as exc:
        raise ParseError("malformed CSV row", detail={"error": str(exc)}) from exc


def _map_row(row: list[str], columns: list[str], skip_empty: bool) -> dict[str, Any]:
    """Zip ``row`` against ``columns``, capturing extras and marking truncation."""
    result: dict[str, Any] = {}
    for index, name in enumerate(columns):
        if index >= len(row):
            result["_truncated"] = True
            break
        result[name] = _clean(row[index], skip_empty)
    for index in range(len(columns), len(row)):
        result[f"_extra.{index}"] = _clean(row[index], skip_empty)
    return result


def _clean(value: str, skip_empty: bool) -> str | None:
    """Return ``None`` for an empty field when ``skip_empty`` is set, else the value."""
    return None if (skip_empty and value == "") else value
