"""Tests for :mod:`ulpf.parse.dsl.loader`."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from ulpf.parse.dsl.loader import SourceRegistry, evaluate_detect
from ulpf.parse.dsl.schema import DetectRule


def _definition(name: str, detect: dict[str, Any], *, priority: int | None = None) -> str:
    body: dict[str, Any] = {
        "name": name,
        "version": "1.0.0",
        "vendor": "Vendor",
        "product": "Product",
        "product_version": "1",
        "detect": detect,
        "parse": {"engine": "kv", "options": {}},
        "normalize": {"class_uid": 4001, "category_uid": 4, "activity_id": 1},
    }
    if priority is not None:
        body["priority"] = priority
    return yaml.safe_dump(body, sort_keys=True)


def _write(directory: Path, name: str, detect: dict[str, Any], **kw: Any) -> None:
    (directory / f"{name}.yaml").write_text(_definition(name, detect, **kw), encoding="utf-8")


def _wait_for(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# --------------------------------------------------------------------------
# detect-rule evaluation


def test_evaluate_detect_covers_every_rule_type() -> None:
    fields = {"proto": "6", "action": "deny"}
    assert evaluate_detect(DetectRule.model_validate({"contains": "ASA"}), "%ASA-6-1", fields)
    assert evaluate_detect(DetectRule.model_validate({"starts_with": "<13>"}), "<13>x", fields)
    assert evaluate_detect(
        DetectRule.model_validate({"regex": r"ASA-\d-\d+"}), "%ASA-6-302013", fields
    )
    assert evaluate_detect(
        DetectRule.model_validate({"field_equals": {"name": "proto", "value": 6}}), "x", fields
    )  # "6" == 6 via string fallback
    assert evaluate_detect(
        DetectRule.model_validate(
            {"all": [{"contains": "ASA"}, {"field_equals": {"name": "action", "value": "deny"}}]}
        ),
        "%ASA-6",
        fields,
    )
    assert not evaluate_detect(
        DetectRule.model_validate({"any": [{"contains": "ZZ"}, {"starts_with": "!!"}]}), "x", fields
    )


# --------------------------------------------------------------------------
# load + match


def test_load_all_and_match_ordered_by_priority(tmp_path: Path) -> None:
    _write(tmp_path, "generic_syslog", {"starts_with": "<"}, priority=200)
    _write(tmp_path, "cisco_asa", {"contains": "%ASA-"}, priority=10)
    _write(tmp_path, "fortigate", {"contains": 'devname="FGT'})

    registry = SourceRegistry()
    registry.load_all(tmp_path)
    assert {d.name for d in registry.definitions()} == {
        "generic_syslog",
        "cisco_asa",
        "fortigate",
    }
    # both generic_syslog and cisco_asa match this line; lower priority wins
    matched = registry.match_text("<134>%ASA-6-302013: Built connection", {})
    assert matched is not None and matched.name == "cisco_asa"
    # only generic_syslog matches this one
    assert registry.match_text("<13>kernel: nothing special", {}).name == "generic_syslog"
    assert registry.match_text("no markers here", {}) is None


def test_invalid_file_in_directory_is_skipped_not_fatal(tmp_path: Path, caplog: Any) -> None:
    _write(tmp_path, "good", {"contains": "X"})
    (tmp_path / "bad.yaml").write_text(
        "name: good\nparse: {}\n", encoding="utf-8"
    )  # missing sections

    registry = SourceRegistry()
    with caplog.at_level(logging.ERROR, logger="ulpf.parse.dsl.loader"):
        registry.load_all(tmp_path)

    assert [d.name for d in registry.definitions()] == ["good"]
    assert any("rejected" in r.message for r in caplog.records)


# --------------------------------------------------------------------------
# hot reload


def test_hot_reload_picks_up_a_new_file_and_rejects_a_broken_one(
    tmp_path: Path, caplog: Any
) -> None:
    _write(tmp_path, "one", {"contains": "AAA"})
    _write(tmp_path, "two", {"contains": "BBB"})
    _write(tmp_path, "three", {"contains": "CCC"})

    registry = SourceRegistry()
    registry.load_all(tmp_path)
    assert len(registry.definitions()) == 3
    reloads_after_load = registry.reload_count
    assert registry.last_reload_time is not None

    registry.start_watching()
    try:
        # (1) a valid 4th file must be picked up within 2 seconds
        _write(tmp_path, "four", {"contains": "DDD"})
        assert _wait_for(lambda: registry.get("four") is not None, timeout=2.0), (
            "new definition was not hot-loaded within 2s"
        )
        assert len(registry.definitions()) == 4
        assert registry.reload_count > reloads_after_load

        # (2) a broken file must NOT change the registry, and must log an error
        names_before = {d.name for d in registry.definitions()}
        with caplog.at_level(logging.ERROR, logger="ulpf.parse.dsl.loader"):
            (tmp_path / "broken.yaml").write_text(
                "name: broken\ndetect: {contains: E, regex: F}\n", encoding="utf-8"
            )
            assert _wait_for(
                lambda: any("rejected" in r.message for r in caplog.records), timeout=2.0
            ), "no rejection was logged for the broken file"

        time.sleep(0.3)  # give any (wrong) swap a chance to happen
        assert registry.get("broken") is None
        assert {d.name for d in registry.definitions()} == names_before  # registry unchanged
    finally:
        registry.stop_watching()


def test_previously_valid_file_edited_to_invalid_keeps_old_version(tmp_path: Path) -> None:
    _write(tmp_path, "src", {"contains": "OLD"})
    registry = SourceRegistry()
    registry.load_all(tmp_path)
    registry.start_watching()
    try:
        (tmp_path / "src.yaml").write_text("not: a valid definition\n", encoding="utf-8")
        time.sleep(0.6)
        kept = registry.get("src")
        assert kept is not None
        assert kept.detect.contains == "OLD"  # the good version is still live
    finally:
        registry.stop_watching()
