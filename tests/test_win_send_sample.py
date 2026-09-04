"""The Windows sample-generator script emits lines that match + normalize.

Runs ``scripts/win/send-sample.ps1 -DryRun`` and pushes each line through the
same detect -> parse -> normalize path ``ulpf inspect`` uses. Skipped anywhere
PowerShell is not available (i.e. Linux CI); it is the local Windows guard that
stops the templates from drifting into malformed test data.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ulpf.cli.inspect import build_report
from ulpf.parse.dsl.loader import SourceRegistry

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "win" / "send-sample.ps1"
_SOURCES = Path(__file__).resolve().parent.parent / "configs" / "sources"

_POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")

pytestmark = pytest.mark.skipif(
    _POWERSHELL is None or not _SCRIPT.is_file(), reason="PowerShell / the script is not available"
)

# script -Source  ->  the source definition its lines must match
_EXPECT = {
    "cisco_asa": "cisco_asa",
    "fortigate_traffic": "fortigate_traffic",
    "panos": "panos_traffic_v10",
    "suricata": "suricata_eve_flow",
    "zeek": "zeek_conn",
    "iptables": "iptables",
}


def _emit(source: str, count: int = 3) -> list[str]:
    assert _POWERSHELL is not None  # guarded by pytestmark
    cmd = [
        _POWERSHELL,
        "-NoProfile",
        "-File",
        str(_SCRIPT),
        "-Source",
        source,
        "-Count",
        str(count),
        "-DryRun",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)  # noqa: S603
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


@pytest.fixture(scope="module")
def registry() -> SourceRegistry:
    reg = SourceRegistry()
    reg.load_all(_SOURCES)
    return reg


@pytest.mark.parametrize(("source", "expected"), sorted(_EXPECT.items()))
def test_each_sample_line_matches_and_normalizes(
    source: str, expected: str, registry: SourceRegistry
) -> None:
    lines = _emit(source, count=3)
    assert len(lines) == 3
    assert len(set(lines)) == 3  # -Count makes each line distinct

    for line in lines:
        report = build_report(line.encode("utf-8"), registry, with_crosswalk=False)
        assert report["match"]["matched"] is True, line
        assert report["match"]["name"] == expected, line
        assert report["validation"]["valid"] is True, line


def test_fortigate_line_is_bare_pri_no_rfc3164_stamp() -> None:
    (line,) = _emit("fortigate_traffic", count=1)
    # the whole point: `<189>` is followed immediately by `date=`, not by a
    # `Mon DD HH:MM:SS host` header that would be eaten as the syslog TAG.
    assert line.startswith("<189>date=")
