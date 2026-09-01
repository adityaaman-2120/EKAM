"""Tests for :mod:`ulpf.cli.main`."""

from __future__ import annotations

import json

import yaml
from typer.testing import CliRunner

from ulpf import __version__
from ulpf.cli.main import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"ulpf {__version__}"


def test_config_show_yaml_is_the_merged_config() -> None:
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    data = yaml.safe_load(result.stdout)
    assert data["ingest"]["syslog_udp_port"] == 514
    assert data["ingest"]["syslog_tls_port"] == 6514
    assert data["storage"]["bronze_path"].endswith("bronze")
    assert data["pipeline"]["worker_count"] == 4


def test_config_show_json_flag() -> None:
    result = runner.invoke(app, ["config", "show", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["api"]["port"] == 8080
    assert data["ingest"]["http_max_body_bytes"] == 8_388_608


def test_run_has_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "listeners" in result.stdout.lower()


def test_bare_invocation_shows_help() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code != 0 or "Usage" in result.stdout
