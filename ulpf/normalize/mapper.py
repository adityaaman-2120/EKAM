"""Field mapper — turns a flat parsed-field dict into a nested OCSF record.

Given a :class:`~ulpf.parse.dsl.schema.SourceDefinition`'s ``normalize`` block
and the flat ``{key: value}`` dict a parse engine produced, :class:`Mapper`
builds the nested OCSF object:

* **Dotted targets nest** — ``"src_endpoint.ip"`` becomes
  ``{"src_endpoint": {"ip": ...}}``.
* **``from`` may be a list** — the first present, non-empty source field is
  taken; when a ``format`` is given and there are several sources they are
  concatenated (space-joined) first, so ``date`` + ``time`` fields combine into
  one timestamp.
* **Type coercion** — ``int`` / ``float`` / ``bool`` / ``ip`` (validated with
  :mod:`ipaddress`) / ``timestamp`` (via
  :func:`ulpf.core.timeutil.parse_timestamp`, UTC epoch nanoseconds) / ``str``.
  A value that cannot be coerced raises :class:`~ulpf.core.errors.MappingError`
  so the event is dead-lettered rather than normalized wrongly.
* **``map``** translates source values to target values verbatim, with
  ``default`` when the source is missing or unmatched.
* **``required``** mappings that resolve to ``None`` raise ``MappingError``.

**Requirement (a), at the field level:** every consumed source field is tracked;
with ``unmapped: keep_all`` every field that was *not* consumed is copied
verbatim into ``ocsf["unmapped"]`` so nothing a parser extracted is ever lost.

**Requirement (d):** ``metadata.uid`` is always set to the event UID and
``metadata.log_hash`` to the raw SHA-256, tying the OCSF record to the exact
bytes in the bronze store.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping as MappingABC
from typing import Any

from ulpf.core.errors import MappingError, ParseError
from ulpf.core.models import NormalizedEvent, ParsedEvent
from ulpf.core.timeutil import parse_timestamp
from ulpf.parse.dsl.schema import ActivityFromSpec, FieldMapping, SourceDefinition

_TRUE_STRINGS = frozenset({"true", "t", "yes", "y", "1", "on"})
_FALSE_STRINGS = frozenset({"false", "f", "no", "n", "0", "off", ""})


class Mapper:
    """Applies a source definition's field mappings to produce an OCSF record."""

    def to_ocsf(
        self,
        definition: SourceDefinition,
        fields: MappingABC[str, Any],
        *,
        event_uid: str,
        raw_hash: str,
    ) -> dict[str, Any]:
        """Build the nested OCSF dict for one parsed event."""
        spec = definition.normalize
        ocsf: dict[str, Any] = {}
        consumed: set[str] = set()

        for dotted, value in spec.constants.items():
            _set_nested(ocsf, dotted, value)

        ocsf["class_uid"] = spec.class_uid
        ocsf["category_uid"] = spec.category_uid
        activity = self._activity_id(spec.activity_id, fields, consumed)
        if activity is not None:
            ocsf["activity_id"] = activity
            if isinstance(activity, int):
                ocsf["type_uid"] = spec.class_uid * 100 + activity

        for path, mapping in spec.fields.items():
            mapped = self._map_one(path, mapping, fields, consumed)
            if mapped is not None:
                _set_nested(ocsf, path, mapped)

        _set_nested(ocsf, "metadata.uid", event_uid)  # requirement (d)
        _set_nested(ocsf, "metadata.log_hash", raw_hash)  # requirement (d)

        self._attach_unmapped(ocsf, spec.unmapped, fields, consumed)  # requirement (a)
        return ocsf

    def apply(
        self,
        definition: SourceDefinition,
        fields: MappingABC[str, Any],
        *,
        event_uid: str,
        raw_hash: str,
    ) -> dict[str, Any]:
        """Alias for :meth:`to_ocsf` (the name the pipeline's NormalizeStage uses)."""
        return self.to_ocsf(definition, fields, event_uid=event_uid, raw_hash=raw_hash)

    def normalize(self, definition: SourceDefinition, event: ParsedEvent) -> NormalizedEvent:
        """Map ``event`` and wrap the result as a :class:`NormalizedEvent`."""
        ocsf = self.to_ocsf(
            definition, event.fields, event_uid=event.event_uid, raw_hash=event.raw_hash
        )
        return NormalizedEvent(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            ingest_time_ns=event.ingest_time_ns,
            ocsf=ocsf,
            source_type=definition.name,
            mapping_version=definition.version,
            enrichment={},
        )

    # -- internals -------------------------------------------------------

    def _activity_id(
        self, spec_value: int | ActivityFromSpec, fields: MappingABC[str, Any], consumed: set[str]
    ) -> int | None:
        """Resolve ``activity_id`` from a static int or a ``{from, map, default}`` spec."""
        if isinstance(spec_value, int):
            return spec_value
        source = fields.get(spec_value.from_)
        if _is_present(source):
            consumed.add(spec_value.from_)
            return spec_value.map.get(str(source), spec_value.default)
        return spec_value.default

    def _map_one(
        self,
        path: str,
        mapping: FieldMapping,
        fields: MappingABC[str, Any],
        consumed: set[str],
    ) -> Any:
        """Resolve one field mapping; return the value, or ``None`` to skip it."""
        raw, used = _resolve_source(mapping, fields)
        if raw is None:
            value = mapping.default  # defaults are used verbatim
        else:
            consumed.update(used)
            if mapping.map is not None:
                value = mapping.map.get(str(raw), mapping.default)
            else:
                value = _coerce(raw, mapping, path)

        if value is None:
            if mapping.required:
                raise MappingError(
                    f"required mapping {path!r} resolved to None",
                    detail={"target": path, "from": mapping.from_, "reason": "required_unresolved"},
                )
            return None
        return value

    def _attach_unmapped(
        self,
        ocsf: dict[str, Any],
        mode: str | list[str],
        fields: MappingABC[str, Any],
        consumed: set[str],
    ) -> None:
        """Copy leftover (unconsumed) source fields into ``ocsf["unmapped"]``."""
        if mode == "drop":
            return
        if mode == "keep_all":
            leftovers = {key: value for key, value in fields.items() if key not in consumed}
        else:  # an explicit keep-list
            leftovers = {key: fields[key] for key in mode if key in fields and key not in consumed}
        ocsf["unmapped"] = leftovers


def _resolve_source(mapping: FieldMapping, fields: MappingABC[str, Any]) -> tuple[Any, list[str]]:
    """Return ``(value, consumed_keys)`` for a mapping's ``from`` (``value`` None if absent)."""
    sources = [mapping.from_] if isinstance(mapping.from_, str) else list(mapping.from_)

    if mapping.format is not None and len(sources) > 1:  # concat mode (date + time -> timestamp)
        present = [key for key in sources if _is_present(fields.get(key))]
        if not present:
            return None, []
        return " ".join(str(fields[key]) for key in present), present

    for key in sources:  # first present, non-empty
        if _is_present(fields.get(key)):
            return fields[key], [key]
    return None, []


def _coerce(raw: Any, mapping: FieldMapping, path: str) -> Any:
    """Coerce a raw source value to ``mapping.type``; raise ``MappingError`` on failure."""
    field_type = mapping.type
    try:
        if field_type == "str":
            return raw if isinstance(raw, str) else str(raw)
        if field_type == "int":
            return _to_int(raw)
        if field_type == "float":
            return float(raw)
        if field_type == "bool":
            return _to_bool(raw)
        if field_type == "ip":
            return str(ipaddress.ip_address(str(raw).strip()))
        if field_type == "timestamp":
            return parse_timestamp(raw, fmt=mapping.format, tz=mapping.tz)
    except (ValueError, TypeError, ParseError) as exc:
        raise MappingError(
            f"could not coerce {path!r} to {field_type}",
            detail={
                "target": path,
                "value": _short(raw),
                "type": field_type,
                "reason": f"invalid_{field_type}",
                "error": str(exc),
            },
        ) from exc
    raise MappingError(f"unknown field type {field_type!r}", detail={"target": path})


def _to_int(raw: Any) -> int:
    """Coerce to ``int``, refusing bools and non-integral floats/strings."""
    if isinstance(raw, bool):
        raise ValueError("refusing to coerce bool to int")
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    try:
        return int(text)
    except ValueError:
        number = float(text)
        if number.is_integer():
            return int(number)
        raise ValueError(f"{text!r} is not an integer") from None


def _to_bool(raw: Any) -> bool:
    """Coerce common textual booleans (``T``/``F``, ``true``/``false``, ``1``/``0``, ...)."""
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in _TRUE_STRINGS:
        return True
    if text in _FALSE_STRINGS:
        return False
    raise ValueError(f"{raw!r} is not a boolean")


def _set_nested(target: dict[str, Any], dotted: str, value: Any) -> None:
    """Assign ``value`` at a dotted path, creating intermediate dicts as needed."""
    keys = dotted.split(".")
    node = target
    for key in keys[:-1]:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    node[keys[-1]] = value


def _is_present(value: Any) -> bool:
    """Whether a source value counts as supplied (not ``None``, not empty string)."""
    return value is not None and value != ""


def _short(value: Any) -> str:
    """A length-capped repr for error detail."""
    text = repr(value)
    return text if len(text) <= 200 else text[:200] + "..."
