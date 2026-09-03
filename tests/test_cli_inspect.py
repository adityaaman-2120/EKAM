"""Tests for :mod:`ulpf.cli.inspect` (the ``ulpf inspect`` debug command)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from ulpf.cli.inspect import build_report
from ulpf.cli.main import app
from ulpf.parse.dsl.loader import SourceRegistry

runner = CliRunner()

_REPO = Path(__file__).resolve().parent.parent
_SOURCES = _REPO / "configs" / "sources"
_FIXTURES = _REPO / "tests" / "fixtures"

_ASA_LINE = (
    "<134>Oct 11 22:14:15 fw01 %ASA-6-302013: Built outbound TCP connection 12345 "
    "for outside:203.0.113.9/443 (203.0.113.9/443) "
    "to inside:192.0.2.15/51234 (198.51.100.7/51234)"
)
_FORTI_LINE = (
    (_FIXTURES / "fortigate_traffic_accept.log").read_text(encoding="utf-8").splitlines()[0]
)
# Private source (RFC 1918) -> genuinely public destination, denied to RDP.
_ENRICH_LINE = (
    'date=2019-05-10 time=11:50:48 logid="0001000014" type="traffic" subtype="forward" '
    "srcip=10.20.30.40 srcport=62024 dstip=8.8.8.8 dstport=3389 proto=6 "
    'action="deny" sentbyte=120 rcvdbyte=0'
)


def _registry() -> SourceRegistry:
    registry = SourceRegistry()
    registry.load_all(_SOURCES)
    return registry


# --------------------------------------------------------------------------
# build_report — the stage-by-stage trace


def test_report_matches_a_source_and_normalizes() -> None:
    report = build_report(_ASA_LINE.encode("utf-8"), _registry(), with_crosswalk=False)

    assert report["raw"]["bytes"] == len(_ASA_LINE.encode("utf-8"))
    assert len(report["raw"]["sha256"]) == 64
    assert report["raw"]["event_uid"]
    assert report["sniff"] == {"outer": "syslog", "inner": "unknown"}

    assert report["match"]["matched"] is True
    assert report["match"]["name"] == "cisco_asa"
    assert report["match"]["version"] == "1.0.0"
    assert report["match"]["product_version"] == "9.x"

    assert report["parsed"]["src_ip"] == "192.0.2.15"
    assert report["normalized"]["class_uid"] == 4001
    assert report["normalized"]["src_endpoint"]["ip"] == "192.0.2.15"

    assert report["validation"]["valid"] is True
    assert 0.0 < report["validation"]["completeness_pct"] <= 100.0

    assert report["unmapped"]["count"] >= 1
    assert "xlate_src_ip" in report["unmapped"]["keys"]


def test_report_runs_the_enrichment_chain_with_network_context() -> None:
    report = build_report(_ENRICH_LINE.encode("utf-8"), _registry(), with_crosswalk=False)

    enrichment = report["enrichment"]
    assert enrichment["ran"] is True

    # the merged enrichments dict is populated and carries a NON-EMPTY network context
    net = enrichment["enrichments"]["network_context"]
    assert net["ips"]["10.20.30.40"]["is_private"] is True
    assert net["ips"]["8.8.8.8"]["is_private"] is False
    assert net["direction"] == "outbound"
    assert net["src_zone"] == "corp"  # 10.0.0.0/8 in configs/assets.yaml

    # the same values are on the normalized record and promoted into OCSF
    assert report["normalized"]["enrichments"]["network_context"]["src_zone"] == "corp"
    assert report["normalized"]["connection_info"]["direction"] == "Outbound"

    by_name = {row["name"]: row for row in enrichment["enrichers"]}
    assert by_name["network_context"]["status"] == "produced"
    assert by_name["network_context"]["latency_ms"] >= 0.0
    assert by_name["attack_tagger"]["status"] == "produced"
    assert enrichment["enrichments"]["attack"]["technique_ids"] == ["T1110"]

    # geoip: cleanly disabled (no .mmdb), never an error
    assert by_name["geoip"]["status"] == "disabled"
    assert "database" in by_name["geoip"]["reason"]


def test_report_no_match_carries_a_parse_note() -> None:
    report = build_report(b"just an ordinary sentence", _registry(), with_crosswalk=False)

    assert report["match"]["matched"] is False
    assert "no source definition" in report["match"]["parse_note"]
    assert report["validation"] is None
    assert report["normalized"]["unmapped"] == {}
    assert report["unmapped"]["count"] == 0


def test_report_crosswalk_only_when_requested() -> None:
    plain = build_report(_FORTI_LINE.encode("utf-8"), _registry(), with_crosswalk=False)
    assert "crosswalk" not in plain

    crossed = build_report(_FORTI_LINE.encode("utf-8"), _registry(), with_crosswalk=True)
    assert crossed["crosswalk"]["ecs"]["source"]["ip"] == "192.0.2.15"
    assert crossed["crosswalk"]["cim"]["src"] == "192.0.2.15"
    assert "network" in crossed["crosswalk"]["cim"]["tags"]


# --------------------------------------------------------------------------
# the CLI surface


def test_inspect_is_registered_on_the_app() -> None:
    result = runner.invoke(app, ["inspect", "--help"])
    assert result.exit_code == 0
    assert "--line" in result.stdout and "--crosswalk" in result.stdout


def test_inspect_line_renders_all_sections() -> None:
    result = runner.invoke(app, ["inspect", "--line", _ASA_LINE])
    assert result.exit_code == 0
    for section in (
        "RAW",
        "SNIFF",
        "MATCH",
        "PARSED",
        "NORMALIZED",
        "ENRICHMENT",
        "VALIDATION",
        "UNMAPPED",
    ):
        assert section in result.stdout
    assert "cisco_asa" in result.stdout


def test_inspect_file_shows_enrichment_section_with_network_context(tmp_path: Path) -> None:
    log = tmp_path / "enrich.log"
    log.write_text(_ENRICH_LINE + "\n", encoding="utf-8")
    result = runner.invoke(app, ["inspect", "--file", str(log)])
    assert result.exit_code == 0
    assert "6 . ENRICHMENT" in result.stdout
    assert "network_context" in result.stdout
    assert "produced" in result.stdout
    assert "geoip" in result.stdout and "disabled" in result.stdout
    # the geoip 'DISABLED' warning log must not leak into the output (the
    # ENRICHMENT panel already reports it) — nothing prints above the RAW panel
    assert "geoip enricher DISABLED" not in result.output
    assert result.stdout.index("1 . RAW") < result.stdout.index("6 . ENRICHMENT")

    payload = runner.invoke(app, ["inspect", "--json", "--file", str(log)])
    report = json.loads(payload.stdout)
    assert report["enrichment"]["enrichments"]["network_context"]["ips"]  # non-empty
    assert report["enrichment"]["enrichments"]["network_context"]["direction"] == "outbound"


def test_inspect_sniff_panel_flags_source_handled_unknown() -> None:
    # Cisco ASA: inner format is "unknown" but the source pattern parses it.
    matched = runner.invoke(app, ["inspect", "--line", _ASA_LINE])
    assert "handled by source pattern" in matched.stdout

    # A genuinely unrecognised line keeps a bare "unknown".
    unmatched = runner.invoke(app, ["inspect", "--line", "just an ordinary sentence"])
    assert "handled by source pattern" not in unmatched.stdout


def test_inspect_json_flag_emits_a_parsable_report() -> None:
    result = runner.invoke(app, ["inspect", "--json", "--line", _ASA_LINE])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["match"]["name"] == "cisco_asa"
    assert report["normalized"]["class_uid"] == 4001


def test_inspect_quiet_flag_prints_only_the_ocsf_record() -> None:
    result = runner.invoke(app, ["inspect", "--quiet", "--line", _ASA_LINE])
    assert result.exit_code == 0
    record = json.loads(result.stdout)
    assert record["class_uid"] == 4001
    assert "src_endpoint" in record


def test_inspect_requires_exactly_one_input_source() -> None:
    assert runner.invoke(app, ["inspect"]).exit_code != 0
    both = runner.invoke(app, ["inspect", "--line", "x", "--file", "pyproject.toml"])
    assert both.exit_code != 0


def test_inspect_file_respects_limit(tmp_path: Path) -> None:
    log = tmp_path / "sample.log"
    log.write_text("\n".join([_ASA_LINE, _FORTI_LINE, _ASA_LINE, _FORTI_LINE]), encoding="utf-8")
    result = runner.invoke(app, ["inspect", "--json", "--file", str(log), "--limit", "2"])
    assert result.exit_code == 0
    reports = [json.loads(block) for block in _json_objects(result.stdout)]
    assert len(reports) == 2


def _json_objects(text: str) -> list[str]:
    """Split a stream of pretty-printed top-level JSON objects."""
    blocks: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                blocks.append(text[start : index + 1])
    return blocks
