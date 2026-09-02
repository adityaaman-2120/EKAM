"""Tests for :mod:`ulpf.parse.dsl.schema` — the source-definition DSL."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from ulpf.parse.dsl.schema import (
    DetectRule,
    FieldMapping,
    SourceDefinition,
    json_schema,
    load_source_definition,
)


def _valid_def() -> dict[str, Any]:
    return {
        "name": "cisco_asa",
        "version": "1.0.0",
        "vendor": "Cisco",
        "product": "ASA",
        "product_version": "9.x",
        "detect": {
            "all": [
                {"contains": "%ASA-"},
                {"any": [{"starts_with": "<"}, {"regex": r"%ASA-\d-\d+"}]},
            ]
        },
        "parse": {
            "envelope": "syslog",
            "engine": "grok",
            "options": {"pattern": "%{GREEDYDATA:msg}"},
        },
        "normalize": {
            "class_uid": 4001,
            "category_uid": 4,
            "activity_id": {
                "from": "action",
                "map": {"Built": 1, "Teardown": 2},
                "default": 0,
            },
            "fields": {
                "src_endpoint.ip": {"from": "src_ip", "type": "ip"},
                "time": {
                    "from": ["timestamp", "envelope.timestamp"],
                    "type": "timestamp",
                    "format": "%b %d %H:%M:%S",
                    "tz": "UTC",
                },
                "severity_id": {
                    "from": "sev",
                    "type": "int",
                    "map": {"6": 1},
                    "default": 1,
                    "required": True,
                },
            },
            "constants": {"metadata.product.name": "Cisco ASA"},
            "unmapped": "keep_all",
        },
        "validate": {"required": ["src_endpoint.ip", "time"], "on_failure": "dead_letter"},
        "enabled": True,
    }


def _with(**overrides: Any) -> dict[str, Any]:
    data = copy.deepcopy(_valid_def())
    for dotted, value in overrides.items():
        node = data
        *parents, last = dotted.split(".")
        for key in parents:
            node = node[key]
        node[last] = value
    return data


def test_valid_definition_parses() -> None:
    sd = load_source_definition(_valid_def())
    assert isinstance(sd, SourceDefinition)
    assert sd.name == "cisco_asa"
    assert sd.parse.engine == "grok"
    assert sd.parse.envelope == "syslog"
    assert sd.normalize.class_uid == 4001
    assert sd.normalize.unmapped == "keep_all"
    assert sd.detect.all is not None and len(sd.detect.all) == 2
    assert sd.normalize.fields["time"].from_ == ["timestamp", "envelope.timestamp"]
    assert sd.validation.on_failure == "dead_letter"
    assert sd.enabled is True


def test_activity_id_may_be_a_static_int() -> None:
    sd = load_source_definition(_with(**{"normalize.activity_id": 6}))
    assert sd.normalize.activity_id == 6


def test_enabled_defaults_true_and_validate_defaults_empty() -> None:
    data = _valid_def()
    del data["enabled"]
    del data["validate"]
    sd = load_source_definition(data)
    assert sd.enabled is True
    assert sd.validation.required == []


# --------------------------------------------------------------------------
# invalid definitions — each must name the offending path


def test_unknown_engine_names_the_field() -> None:
    with pytest.raises(ValidationError) as exc_info:
        load_source_definition(_with(**{"parse.engine": "xml"}))
    errors = exc_info.value.errors()
    assert errors[0]["loc"] == ("parse", "engine")
    assert "xml" in str(exc_info.value)


def test_unknown_key_is_rejected_and_located() -> None:
    data = _with()
    data["parse"]["optionz"] = {}
    with pytest.raises(ValidationError) as exc_info:
        load_source_definition(data)
    (err,) = exc_info.value.errors()
    assert err["loc"] == ("parse", "optionz")
    assert "extra" in err["msg"].lower()


def test_detect_rule_requires_exactly_one_alternative() -> None:
    with pytest.raises(ValidationError) as exc_info:
        DetectRule.model_validate({"contains": "x", "regex": "y"})
    assert "exactly one" in str(exc_info.value)


def test_detect_regex_must_compile() -> None:
    with pytest.raises(ValidationError) as exc_info:
        DetectRule.model_validate({"regex": "(unclosed"})
    err = exc_info.value.errors()[0]
    assert err["loc"] == ("regex",)
    assert "invalid regex" in err["msg"]


def test_grok_engine_without_pattern_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        load_source_definition(_with(**{"parse.options": {}}))
    assert "pattern" in str(exc_info.value)


def test_format_and_tz_only_apply_to_timestamps() -> None:
    with pytest.raises(ValidationError) as exc_info:
        FieldMapping.model_validate({"from": "x", "type": "int", "format": "%Y"})
    assert "type: timestamp" in str(exc_info.value)


def test_source_name_must_be_a_slug() -> None:
    with pytest.raises(ValidationError) as exc_info:
        load_source_definition(_with(name="Cisco ASA!"))
    err = exc_info.value.errors()[0]
    assert err["loc"] == ("name",)
    assert "slug" in err["msg"]


def test_field_mapping_from_alias_and_populate_by_name() -> None:
    by_alias = FieldMapping.model_validate({"from": "src_ip", "type": "ip"})
    by_name = FieldMapping.model_validate({"from_": "src_ip", "type": "ip"})
    assert by_alias.from_ == by_name.from_ == "src_ip"


# --------------------------------------------------------------------------
# JSON Schema export


def test_json_schema_export_is_serialisable_and_complete() -> None:
    schema = json_schema()
    assert schema["title"] == "ULPF Source Definition"
    assert json.dumps(schema)  # round-trips as JSON

    props = schema["properties"]
    for section in ("name", "detect", "parse", "normalize", "validate", "enabled"):
        assert section in props

    defs = schema["$defs"]
    assert "DetectRule" in defs  # recursive model exported once, referenced by $ref
    assert "FieldMapping" in defs and "OcsfSpec" in defs
