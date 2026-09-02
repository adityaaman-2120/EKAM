"""Phase-3 end-to-end: every source definition in ``configs/sources/`` parses + normalizes.

For each shipped source definition this drives the DSL-defined **parse** path
(strip the syslog envelope, run the declared engine with the declared options)
followed by the **normalize** path (``SourceRegistry.match`` -> ``Mapper`` ->
``finalize`` -> ``OcsfValidator``), and asserts the contract every onboarded
perimeter source must meet:

1. ``SourceRegistry`` routes the source's own fixture line to that definition.
2. the finalized OCSF record validates against its class profile.
3. normalization completeness is above 0.6.
4. ``event_uid`` / ``raw_hash`` survive into the record (requirement d, traceability).
5. ``unmapped`` is non-empty, and for sources carrying attributes OCSF 1.5.0 has
   no home for (NAT address pairs, firewall zones) those exact keys are present.

Plus: a brand-new ``*.yaml`` dropped into the sources directory at runtime is
hot-reloaded into the *same* registry instance and is immediately usable
(requirement e).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from ulpf.core.models import ParsedEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition, load_source_definition
from ulpf.parse.engines.csv_engine import CsvEngine
from ulpf.parse.engines.grok_engine import GrokEngine
from ulpf.parse.engines.json_engine import JsonEngine
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.engines.util import flatten
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_HERE = Path(__file__).parent
_SOURCES = _HERE.parent / "configs" / "sources"
_FIXTURES = _HERE / "fixtures"

_ENGINES = {"json": JsonEngine, "kv": KvEngine, "csv": CsvEngine, "grok": GrokEngine}


@dataclass(frozen=True)
class Case:
    """One source definition, the fixture that exercises it, and its OCSF class."""

    fixture: str
    class_uid: int
    ocsf_gap_keys: tuple[str, ...] = ()  # attrs OCSF can't hold -> must be in `unmapped`
    routes_to: str | None = None  # the name detect resolves to, if not this one

    def route(self, name: str) -> str:
        """The definition name the registry is expected to return for this fixture."""
        return self.routes_to or name


# One representative fixture per shipped source definition. ``panos_traffic_v11``
# is content-identical to v10 on the wire (the field *order* differs, which is an
# operator-pinned deployment fact, not something detect can see), so its line
# routes to the lower-sorted ``panos_traffic_v10`` — see the panos_traffic_v10.yaml
# header. Normalization below still uses each pinned version's own definition.
_CASES: dict[str, Case] = {
    "cisco_asa": Case("cisco_asa_302013.log", 4001, ("xlate_src_ip",)),
    "fortigate_traffic": Case("fortigate_traffic_accept.log", 4001, ("transip",)),
    "panos_traffic_v10": Case("panos_traffic_v10.log", 4001, ("nat_src_ip", "src_zone")),
    "panos_traffic_v11": Case(
        "panos_traffic_v11.log", 4001, ("nat_src_ip", "src_zone"), routes_to="panos_traffic_v10"
    ),
    "iptables": Case("iptables_drop.log", 4001),
    "aws_vpc_flow": Case("aws_vpc_flow_accept.log", 4001),
    "suricata_eve_alert": Case("suricata_eve_alert.jsonl", 2004),
    "suricata_eve_flow": Case("suricata_eve_flow.jsonl", 4001),
    "zeek_conn": Case("zeek_conn.jsonl", 4001, ("history",)),
    "zeek_dns": Case("zeek_dns.jsonl", 4003),
    "zeek_http": Case("zeek_http.jsonl", 4002),
}


@pytest.fixture(scope="module")
def registry() -> SourceRegistry:
    """A registry loaded from the real ``configs/sources/`` directory."""
    reg = SourceRegistry()
    reg.load_all(_SOURCES)
    return reg


def _definition(name: str) -> SourceDefinition:
    return load_source_definition(yaml.safe_load((_SOURCES / f"{name}.yaml").read_text("utf-8")))


def _first_line(fixture: str) -> bytes:
    return (_FIXTURES / fixture).read_bytes().splitlines()[0]


def _dsl_fields(sd: SourceDefinition, raw_bytes: bytes) -> dict[str, Any]:
    """The DSL-defined parse: strip the envelope, run the declared engine + options."""
    engine = _ENGINES[sd.parse.engine]()
    if sd.parse.envelope == "syslog":
        envelope, message = parse_syslog_envelope(raw_bytes)
        fields = dict(engine.parse(message.decode("utf-8", "replace"), sd.parse.options))
        fields.update(flatten(envelope, prefix="envelope"))  # coordinator merges this too
        return fields
    return dict(engine.parse(raw_bytes.decode("utf-8", "replace"), sd.parse.options))


def _match_fields(text: str) -> dict[str, Any]:
    """Best-effort generic fields, for detect rules that use ``field_equals``."""
    if text.lstrip().startswith("{"):
        try:
            return JsonEngine().parse(text, {})
        except Exception:  # noqa: BLE001 - a non-JSON line just has no generic fields
            return {}
    return {}


def _normalize(sd: SourceDefinition, raw_bytes: bytes):  # noqa: ANN202 - (NormalizedEvent, dict)
    """Run the full parse + normalize path for one line; return (event, finalized ocsf)."""
    raw = make_raw_event(raw_bytes, source_id=sd.name, transport="file")
    parsed = ParsedEvent(**raw.model_dump(), format="unknown", fields=_dsl_fields(sd, raw_bytes))
    event = Mapper().normalize(sd, parsed)
    return raw, event, finalize(event.ocsf)


def test_every_shipped_source_has_a_phase3_case() -> None:
    shipped = {path.stem for path in _SOURCES.glob("*.yaml")}
    assert shipped == set(_CASES), shipped.symmetric_difference(_CASES)


@pytest.mark.parametrize("name", sorted(_CASES))
def test_source_parses_and_normalizes_end_to_end(name: str, registry: SourceRegistry) -> None:
    case = _CASES[name]
    raw_bytes = _first_line(case.fixture)
    text = raw_bytes.decode("utf-8", "replace")

    # 1. the registry routes this line to its own definition
    matched = registry.match_text(text, _match_fields(text))
    assert matched is not None and matched.name == case.route(name)

    raw, event, ocsf = _normalize(_definition(name), raw_bytes)

    # 2. a valid OCSF record for the expected class
    result = OcsfValidator(record_metrics=False).validate(ocsf)
    assert result.valid, result.errors
    assert ocsf["class_uid"] == case.class_uid

    # 3. completeness above 0.6
    assert result.completeness > 0.6, f"{name}: completeness only {result.completeness:.2f}"

    # 4. traceability (requirement d): uid + hash on the event and inside the record
    assert event.event_uid == raw.event_uid and event.raw_hash == raw.raw_hash
    assert event.traceability() == {"event_uid": raw.event_uid, "raw_hash": raw.raw_hash}
    assert ocsf["metadata"]["uid"] == raw.event_uid
    assert ocsf["metadata"]["log_hash"] == raw.raw_hash

    # 5. nothing a parser produced is lost; OCSF-can't-hold fields land in unmapped
    assert ocsf["unmapped"], f"{name}: unmapped is empty"
    for key in case.ocsf_gap_keys:
        assert key in ocsf["unmapped"], f"{name}: expected {key!r} in unmapped, got {sorted(ocsf['unmapped'])}"


def test_matched_definition_equals_the_definition_used_to_parse(registry: SourceRegistry) -> None:
    """Requirement 1, sharpened: the object the registry returns IS the shipped file."""
    for name, case in _CASES.items():
        text = _first_line(case.fixture).decode("utf-8", "replace")
        matched = registry.match_text(text, _match_fields(text))
        assert matched is not None
        assert matched.name == case.route(name)
        assert matched.normalize.class_uid == case.class_uid
        assert matched.version == _definition(case.route(name)).version


# --------------------------------------------------------------------------
# hot reload (requirement e)


def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


def test_new_source_yaml_is_hot_reloaded_into_the_same_registry(tmp_path: Path) -> None:
    directory = tmp_path / "sources"
    directory.mkdir()
    # start with one real source so the registry is already live and non-empty
    (directory / "zeek_conn.yaml").write_text((_SOURCES / "zeek_conn.yaml").read_text("utf-8"))
    reg = SourceRegistry()
    reg.load_all(directory)

    registry_identity = id(reg)
    reloads_before = reg.reload_count
    assert reg.get("aws_vpc_flow") is None

    reg.start_watching()
    try:
        # drop a brand-new perimeter source definition in at runtime — no restart
        (directory / "aws_vpc_flow.yaml").write_text(
            (_SOURCES / "aws_vpc_flow.yaml").read_text("utf-8")
        )
        assert _wait_for(lambda: reg.get("aws_vpc_flow") is not None), (
            "hot reload did not pick up the new source definition"
        )
    finally:
        reg.stop_watching()

    # same registry object, it just gained a definition
    assert id(reg) == registry_identity
    assert reg.reload_count > reloads_before
    assert reg.get("zeek_conn") is not None  # the original is still there

    new_def = reg.get("aws_vpc_flow")
    assert new_def is not None

    # ...and the new source works end to end immediately
    raw_bytes = _first_line("aws_vpc_flow_accept.log")
    assert reg.match_text(raw_bytes.decode(), {}).name == "aws_vpc_flow"
    _raw, _event, ocsf = _normalize(new_def, raw_bytes)
    assert OcsfValidator(record_metrics=False).validate(ocsf).valid is True
    assert ocsf["class_uid"] == 4001
