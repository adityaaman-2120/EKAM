"""Tests for :mod:`ulpf.normalize.mapper`."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ulpf.core.errors import MappingError
from ulpf.core.models import NormalizedEvent
from ulpf.core.timeutil import parse_timestamp
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.parse.dsl.schema import SourceDefinition, load_source_definition

_UID = "01a05e52-f78a-7a0b-bc34-cf3ce4f6952a"
_HASH = "a" * 64


def _sd(normalize_extra: dict[str, Any], *, unmapped: Any = "drop") -> SourceDefinition:
    return load_source_definition(
        {
            "name": "test_src",
            "version": "2.1.0",
            "vendor": "V",
            "product": "P",
            "product_version": "1",
            "detect": {"contains": "x"},
            "parse": {"engine": "kv", "options": {}},
            "normalize": {
                "class_uid": 4001,
                "category_uid": 4,
                "activity_id": 1,
                "unmapped": unmapped,
                **normalize_extra,
            },
        }
    )


def _ocsf(fields: dict[str, Any], normalize_extra: dict[str, Any], **kw: Any) -> dict[str, Any]:
    sd = _sd(normalize_extra, **kw)
    return Mapper().to_ocsf(sd, fields, event_uid=_UID, raw_hash=_HASH)


# --------------------------------------------------------------------------
# structure + identity


def test_dotted_targets_create_nested_structure() -> None:
    out = _ocsf(
        {"src_ip": "192.0.2.1"}, {"fields": {"src_endpoint.ip": {"from": "src_ip", "type": "ip"}}}
    )
    assert out["src_endpoint"] == {"ip": "192.0.2.1"}
    assert out["class_uid"] == 4001
    assert out["category_uid"] == 4
    assert out["activity_id"] == 1
    assert out["type_uid"] == 4001 * 100 + 1


def test_metadata_uid_and_log_hash_are_always_set() -> None:
    out = _ocsf({}, {"fields": {}})
    assert out["metadata"]["uid"] == _UID
    assert out["metadata"]["log_hash"] == _HASH


def test_constants_are_placed_at_dotted_paths_alongside_metadata() -> None:
    out = _ocsf({}, {"fields": {}, "constants": {"metadata.product.name": "Cisco ASA"}})
    assert out["metadata"]["product"]["name"] == "Cisco ASA"
    assert out["metadata"]["uid"] == _UID


# --------------------------------------------------------------------------
# every type


def test_type_coercions() -> None:
    fields = {"n": "12", "f": "1.5", "b": "T", "b2": "false", "s": 12}
    out = _ocsf(
        fields,
        {
            "fields": {
                "n": {"from": "n", "type": "int"},
                "f": {"from": "f", "type": "float"},
                "b": {"from": "b", "type": "bool"},
                "b2": {"from": "b2", "type": "bool"},
                "s": {"from": "s", "type": "str"},
            }
        },
    )
    assert out["n"] == 12 and isinstance(out["n"], int)
    assert out["f"] == 1.5 and isinstance(out["f"], float)
    assert out["b"] is True
    assert out["b2"] is False
    assert out["s"] == "12"


def test_ip_type_validates() -> None:
    out = _ocsf({"a": "2001:db8::1"}, {"fields": {"a": {"from": "a", "type": "ip"}}})
    assert out["a"] == "2001:db8::1"
    with pytest.raises(MappingError):
        _ocsf({"a": "not-an-ip"}, {"fields": {"a": {"from": "a", "type": "ip"}}})


def test_timestamp_type_uses_parse_timestamp() -> None:
    fields = {"ts": "2026-08-15 22:14:15"}
    spec = {
        "fields": {
            "time": {"from": "ts", "type": "timestamp", "format": "%Y-%m-%d %H:%M:%S", "tz": "UTC"}
        }
    }
    out = _ocsf(fields, spec)
    assert out["time"] == parse_timestamp("2026-08-15 22:14:15", fmt="%Y-%m-%d %H:%M:%S", tz="UTC")
    assert isinstance(out["time"], int)
    with pytest.raises(MappingError):
        _ocsf({"ts": "nonsense"}, spec)


def test_int_coercion_rejects_non_integral() -> None:
    with pytest.raises(MappingError):
        _ocsf({"n": "12.5"}, {"fields": {"n": {"from": "n", "type": "int"}}})


# --------------------------------------------------------------------------
# from-lists, maps, defaults, required


def test_from_list_without_join_coalesces_to_first_present_and_consumes_only_it() -> None:
    out = _ocsf(
        {"b": "hit", "c": "later"},
        {"fields": {"t": {"from": ["a", "b", "c"], "type": "str"}}, "constants": {}},
        unmapped="keep_all",
    )
    assert out["t"] == "hit"
    assert out["unmapped"] == {"c": "later"}  # b consumed, a absent, c left over


def test_from_list_without_join_coalesces_even_with_a_timestamp_format() -> None:
    # A list `from` + `format` but no `join` must NOT concatenate: it coalesces.
    fields = {"eventtime": "2026-08-15 22:14:15", "date": "2026-08-15"}
    out = _ocsf(
        fields,
        {
            "fields": {
                "time": {
                    "from": ["eventtime", "date"],
                    "type": "timestamp",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "tz": "UTC",
                }
            }
        },
        unmapped="keep_all",
    )
    assert out["time"] == parse_timestamp("2026-08-15 22:14:15", fmt="%Y-%m-%d %H:%M:%S", tz="UTC")
    assert out["unmapped"] == {"date": "2026-08-15"}  # only eventtime consumed


def test_from_list_with_join_concatenates_present_values_in_order() -> None:
    fields = {"date": "2019-05-10", "time": "11:50:48"}
    out = _ocsf(
        fields,
        {
            "fields": {
                "time": {
                    "from": ["date", "time"],
                    "join": " ",
                    "type": "timestamp",
                    "format": "%Y-%m-%d %H:%M:%S",
                    "tz": "UTC",
                }
            }
        },
        unmapped="keep_all",
    )
    expected = parse_timestamp("2019-05-10 11:50:48", fmt="%Y-%m-%d %H:%M:%S", tz="UTC")
    assert out["time"] == expected
    assert out["time"] == 1_557_489_048_000_000_000  # 2019-05-10T11:50:48Z in epoch ns
    assert out["unmapped"] == {}  # both date and time consumed


def test_join_with_a_missing_field_concatenates_only_what_is_present() -> None:
    out = _ocsf(
        {"a": "left"},
        {"fields": {"t": {"from": ["a", "b"], "join": "-", "type": "str"}}, "constants": {}},
        unmapped="keep_all",
    )
    assert out["t"] == "left"  # b absent -> just "a"


def test_join_on_a_scalar_from_is_rejected_at_load_time() -> None:
    with pytest.raises(ValidationError, match="'join' only applies when 'from' is a list"):
        _sd({"fields": {"t": {"from": "a", "join": " ", "type": "str"}}})


def test_value_map_translates_and_falls_back_to_default() -> None:
    spec = {"fields": {"severity_id": {"from": "sev", "map": {"6": 1, "4": 3}, "default": 0}}}
    assert _ocsf({"sev": "6"}, spec)["severity_id"] == 1
    assert _ocsf({"sev": "4"}, spec)["severity_id"] == 3
    assert _ocsf({"sev": "9"}, spec)["severity_id"] == 0  # unmatched -> default
    assert _ocsf({}, spec)["severity_id"] == 0  # missing -> default


def test_missing_with_default_uses_the_default() -> None:
    out = _ocsf({}, {"fields": {"x": {"from": "nope", "default": "fallback"}}})
    assert out["x"] == "fallback"


def test_missing_and_required_raises_mapping_error() -> None:
    with pytest.raises(MappingError) as exc_info:
        _ocsf({}, {"fields": {"x": {"from": "nope", "type": "str", "required": True}}})
    assert exc_info.value.detail["target"] == "x"
    assert exc_info.value.detail["reason"] == "required_unresolved"


def test_empty_string_source_is_treated_as_missing() -> None:
    with pytest.raises(MappingError):
        _ocsf({"x": ""}, {"fields": {"x": {"from": "x", "type": "str", "required": True}}})


# --------------------------------------------------------------------------
# unmapped modes — requirement (a)


def test_unmapped_keep_all_captures_every_unconsumed_field() -> None:
    out = _ocsf(
        {"a": 1, "b": 2, "used": "x"},
        {"fields": {"t": {"from": "used", "type": "str"}}},
        unmapped="keep_all",
    )
    assert out["t"] == "x"
    assert out["unmapped"] == {"a": 1, "b": 2}  # nothing a parser extracted is lost


def test_unmapped_drop_omits_the_object() -> None:
    out = _ocsf({"a": 1}, {"fields": {}}, unmapped="drop")
    assert "unmapped" not in out


def test_unmapped_explicit_keeplist() -> None:
    out = _ocsf({"a": 1, "b": 2, "c": 3}, {"fields": {}}, unmapped=["a", "c", "missing"])
    assert out["unmapped"] == {"a": 1, "c": 3}


# --------------------------------------------------------------------------
# activity_id from a map + full NormalizedEvent


def test_activity_id_resolved_from_a_field_map() -> None:
    sd = _sd({"activity_id": {"from": "action", "map": {"Built": 1, "Teardown": 2}, "default": 0}})
    out = Mapper().to_ocsf(sd, {"action": "Teardown"}, event_uid=_UID, raw_hash=_HASH)
    assert out["activity_id"] == 2
    assert out["type_uid"] == 4001 * 100 + 2

    out_default = Mapper().to_ocsf(sd, {"action": "Weird"}, event_uid=_UID, raw_hash=_HASH)
    assert out_default["activity_id"] == 0


def test_normalize_produces_a_normalized_event() -> None:
    raw = make_raw_event(b"<134>x proto=6 src=192.0.2.1", source_id="s", transport="udp")
    from ulpf.core.models import ParsedEvent

    parsed = ParsedEvent(
        **raw.model_dump(),
        format="kv",
        fields={"src": "192.0.2.1", "proto": "6", "extra": "left"},
    )
    sd = _sd(
        {"fields": {"src_endpoint.ip": {"from": "src", "type": "ip"}}},
        unmapped="keep_all",
    )
    normalized = Mapper().normalize(sd, parsed)

    assert isinstance(normalized, NormalizedEvent)
    assert normalized.source_type == "test_src"
    assert normalized.mapping_version == "2.1.0"
    assert normalized.event_uid == raw.event_uid
    assert normalized.raw_hash == raw.raw_hash
    assert normalized.ocsf["src_endpoint"]["ip"] == "192.0.2.1"
    assert normalized.ocsf["metadata"]["uid"] == raw.event_uid
    assert normalized.ocsf["unmapped"] == {"proto": "6", "extra": "left"}
    assert normalized.traceability() == {"event_uid": raw.event_uid, "raw_hash": raw.raw_hash}
