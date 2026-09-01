"""Phase-2 golden tests: one fixture line per engine, asserted against a JSON golden.

Set ``ULPF_WRITE_GOLDEN=1`` to (re)generate ``tests/golden/<case>.json`` from the
current engine output, then inspect the diff and commit.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from ulpf.parse.column_maps import get_column_map
from ulpf.parse.engines.cef_engine import CefEngine
from ulpf.parse.engines.csv_engine import CsvEngine
from ulpf.parse.engines.dissect_engine import DissectEngine
from ulpf.parse.engines.grok_engine import GrokEngine
from ulpf.parse.engines.json_engine import JsonEngine
from ulpf.parse.engines.kv_engine import KvEngine
from ulpf.parse.engines.leef_engine import LeefEngine
from ulpf.parse.engines.tsv_engine import TsvEngine
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_HERE = Path(__file__).parent
_FIXTURES = _HERE / "fixtures"
_GOLDEN = _HERE / "golden"
_WRITE_GOLDEN = os.environ.get("ULPF_WRITE_GOLDEN") == "1"

_ASA_DISSECT = (
    "%{action} %{direction} %{proto} connection %{conn_id} for "
    "%{src_endpoint} %{nat_src} to %{dst_endpoint} %{nat_dst}"
)
_ASA_GROK = (
    r"%{WORD:action} %{WORD:direction} %{WORD:proto} connection %{INT:conn_id} for "
    r"%{NOTSPACE:src_endpoint} \(%{DATA:nat_src}\) to "
    r"%{NOTSPACE:dst_endpoint} \(%{DATA:nat_dst}\)"
)


def _first_line(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes().splitlines()[0]


def _syslog_body(name: str) -> str:
    """The message bytes of a fixture's first line, after the syslog envelope."""
    _envelope, message = parse_syslog_envelope(_first_line(name))
    return message.decode("utf-8", "replace")


def _tsv_event(name: str) -> dict[str, object]:
    """Feed every line of a Zeek TSV fixture through one engine; return the data row."""
    engine = TsvEngine()
    event: dict[str, object] = {}
    for line in (_FIXTURES / name).read_text(encoding="utf-8").splitlines():
        parsed = engine.parse(line, {})
        if parsed:
            event = parsed
    return event


_CASES: dict[str, Callable[[], dict[str, object]]] = {
    "json_suricata": lambda: JsonEngine().parse(
        _first_line("suricata_eve_alert.jsonl").decode("utf-8"), {}
    ),
    "json_zeek_conn": lambda: JsonEngine().parse(
        _first_line("zeek_conn.jsonl").decode("utf-8"), {}
    ),
    "kv_fortigate": lambda: KvEngine().parse(_syslog_body("fortigate.log"), {}),
    "kv_iptables": lambda: KvEngine().parse(_syslog_body("iptables.log"), {}),
    "csv_panos": lambda: CsvEngine().parse(
        _syslog_body("panos.log"), {"columns": get_column_map("panos_traffic", "10.1")}
    ),
    "tsv_zeek_conn": lambda: _tsv_event("zeek_conn.tsv"),
    "cef_sample": lambda: CefEngine().parse(_first_line("cef_sample.log").decode("utf-8"), {}),
    "leef_sample": lambda: LeefEngine().parse(_first_line("leef_sample.log").decode("utf-8"), {}),
    "dissect_cisco_asa": lambda: DissectEngine().parse(
        _syslog_body("cisco_asa.log"), {"pattern": _ASA_DISSECT}
    ),
    "grok_cisco_asa": lambda: GrokEngine().parse(
        _syslog_body("cisco_asa.log"), {"pattern": _ASA_GROK}
    ),
}


@pytest.mark.parametrize("case_id", sorted(_CASES))
def test_engine_output_matches_golden(case_id: str) -> None:
    actual = _CASES[case_id]()
    assert isinstance(actual, dict) and actual, f"{case_id} produced no fields"

    golden_path = _GOLDEN / f"{case_id}.json"
    if _WRITE_GOLDEN or not golden_path.exists():
        golden_path.write_text(
            json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        pytest.fail(f"golden written: tests/golden/{case_id}.json — inspect and re-run")

    expected = json.loads(golden_path.read_text(encoding="utf-8"))
    assert actual == expected
