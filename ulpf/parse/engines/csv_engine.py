"""Positional CSV parse engine (PAN-OS and similar headerless CSV logs).

The row is split with the standard :mod:`csv` reader (so quoting and embedded
delimiters are handled) and mapped onto an ordered ``columns`` list by position.

Options:

* ``columns``    — ordered list of field names (required).
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
from ulpf.parse.registry import registry


@registry.engine
class CsvEngine:
    """Maps a delimited row onto an ordered list of column names."""

    name = "csv"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        """Split ``text`` and map it positionally onto ``options['columns']``."""
        columns = options.get("columns")
        if not columns:
            raise ParseError("csv engine requires a non-empty 'columns' option")
        delimiter = options.get("delimiter", ",")
        quotechar = options.get("quotechar", '"')
        skip_empty = bool(options.get("skip_empty", True))
        if len(delimiter) != 1:
            raise ParseError(
                "delimiter must be a single character", detail={"delimiter": delimiter}
            )

        row = _read_row(text, delimiter, quotechar)
        return _map_row(row, [str(name) for name in columns], skip_empty)


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
