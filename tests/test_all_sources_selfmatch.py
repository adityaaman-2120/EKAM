"""Every source definition must match and correctly normalize its own sample.

Iterates every ``configs/sources/*.yaml``, loads the sample line named in
:data:`ulpf.cli.sources.SAMPLE_FIXTURES`, and asserts the full
match -> parse -> normalize -> validate path. A YAML with no registered fixture
fails loudly, so a source can never be added without one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from ulpf.cli.inspect import _coordinator_fields
from ulpf.cli.sources import (
    _MIN_COMPLETENESS,
    SAMPLE_FIXTURES,
    check_source,
    verify_all,
)
from ulpf.integrity.hashing import make_raw_event
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import load_source_definition

_REPO = Path(__file__).resolve().parent.parent
_SOURCES = _REPO / "configs" / "sources"
_FIXTURES = _REPO / "tests" / "fixtures"

_SOURCE_PATHS = sorted(_SOURCES.glob("*.yaml"))
_SOURCE_NAMES = [p.stem for p in _SOURCE_PATHS]


def _registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.load_all(_SOURCES)
    return registry


def test_every_source_yaml_has_a_registered_fixture_that_exists() -> None:
    """No source may exist without a sample line to verify it against."""
    for path in _SOURCE_PATHS:
        name = load_source_definition(yaml.safe_load(path.read_text("utf-8"))).name
        assert name in SAMPLE_FIXTURES, (
            f"{path.name}: add an entry to ulpf.cli.sources.SAMPLE_FIXTURES"
        )
        fixture = _FIXTURES / SAMPLE_FIXTURES[name]
        assert fixture.is_file(), f"{name}: fixture {fixture.name} is missing"


@pytest.mark.parametrize("source_path", _SOURCE_PATHS, ids=_SOURCE_NAMES)
def test_source_matches_and_normalizes_its_own_fixture(source_path: Path) -> None:
    definition = load_source_definition(yaml.safe_load(source_path.read_text("utf-8")))
    fixture = _FIXTURES / SAMPLE_FIXTURES[definition.name]
    line = fixture.read_text(encoding="utf-8", errors="replace").splitlines()[0]

    check = check_source(definition, _registry(), line)

    # The single loud assertion: any failed expectation lists itself here.
    assert check.ok, f"{definition.name}: {check.problems}"

    # ... and the individual guarantees, spelled out. STRICT: the fixture must
    # be claimed by THIS definition, not merely by *some* definition.
    assert check.matched_name == definition.name, (
        f"{definition.name} fixture was matched by {check.matched_name!r}"
    )
    assert check.class_uid is not None
    assert check.valid is True
    assert check.completeness > _MIN_COMPLETENESS
    assert check.has_uid and check.has_hash
    assert check.unmapped_count > 0  # every source here carries surplus vendor fields


def test_no_source_matches_a_different_vendors_fixture() -> None:
    """Cross-check: each fixture must not be claimed by an unrelated source."""
    registry = _registry()
    for path in _SOURCE_PATHS:
        definition = load_source_definition(yaml.safe_load(path.read_text("utf-8")))
        line = (_FIXTURES / SAMPLE_FIXTURES[definition.name]).read_text("utf-8").splitlines()[0]
        check = check_source(definition, registry, line)
        assert "matched a different source" not in " ".join(check.problems), check.problems


def test_verify_all_reports_no_missing_fixtures_and_no_failures() -> None:
    checks, missing = verify_all(_SOURCES, _FIXTURES)
    assert missing == []
    assert [c.name for c in checks if not c.ok] == []
    assert len(checks) == len(_SOURCE_PATHS)


def test_fortigate_detect_matches_quoted_and_unquoted_forms() -> None:
    """The brittle-quoting fix: `type="traffic"` and `type=traffic` both match."""
    registry = _registry()
    quoted = (
        '<189>date=2026-08-15 time=22:14:15 devname="FGT" logid="0000000013" '
        'type="traffic" srcip=192.0.2.15 dstip=203.0.113.9 action="accept" policyid=1'
    )
    unquoted = (
        "<189>date=2026-08-15 time=22:14:15 devname=FGT logid=0000000013 "
        "type=traffic srcip=192.0.2.15 dstip=203.0.113.9 action=accept policyid=1"
    )
    assert registry.match_text(quoted, {}).name == "fortigate_traffic"
    assert registry.match_text(unquoted, {}).name == "fortigate_traffic"


@pytest.mark.parametrize("source_path", _SOURCE_PATHS, ids=_SOURCE_NAMES)
def test_detect_is_tolerant_of_quoting_around_its_own_fixture(source_path: Path) -> None:
    """Every source still matches its fixture with all `key="v"` quoting stripped.

    This is the quote-fragility audit as an assertion: toggling the quoting of
    every ``key="value"`` pair in a source's own sample must not change whether
    the source's detect rules fire.
    """
    definition = load_source_definition(yaml.safe_load(source_path.read_text("utf-8")))
    registry = _registry()
    line = (_FIXTURES / SAMPLE_FIXTURES[definition.name]).read_text("utf-8").splitlines()[0]

    for variant in (line, _strip_kv_quotes(line), _quote_kv(line)):
        hit = registry.match_text(variant, _fields_for(variant))
        assert hit is not None, f"{definition.name}: no match for {variant[:80]!r}"
        assert hit.name == definition.name, f"{definition.name}: variant matched {hit.name}"


# --------------------------------------------------------------------------
# helpers


def _fields_for(variant: str) -> dict[str, object]:
    """Parsed fields for ``field_equals`` detect rules (Suricata), best effort."""
    event = make_raw_event(variant.encode("utf-8"), source_id="t", transport="file")
    fields, _ = _coordinator_fields(event)
    return fields


def _strip_kv_quotes(line: str) -> str:
    """Turn every ``key="value"`` into ``key=value`` (values without spaces)."""
    return re.sub(r'([A-Za-z0-9_.]+)="([^"\s]*)"', r"\1=\2", line)


def _quote_kv(line: str) -> str:
    """Turn every bare ``key=value`` into ``key="value"``."""
    return re.sub(r'\b([A-Za-z0-9_.]+)=([^"\s,][^\s,]*)', r'\1="\2"', line)
