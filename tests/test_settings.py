"""Tests for :mod:`ulpf.config.settings`."""

from __future__ import annotations

from pathlib import Path

import pytest

from ulpf.config.settings import Settings, get_settings


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    """Ensure each test builds a fresh, uncached Settings instance."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_defaults_load_from_yaml() -> None:
    """Defaults defined in configs/ulpf.yaml are loaded across all sections."""
    settings = get_settings()

    assert settings.ingest.syslog_udp_port == 514
    assert settings.ingest.syslog_tls_port == 6514
    assert settings.ingest.queue_max_size == 100_000
    assert settings.storage.bronze_path == Path("data/runtime/bronze")
    assert settings.storage.ledger_path == Path("data/runtime/ledger")
    assert settings.parse.sources_dir == Path("configs/sources")
    assert settings.parse.hot_reload is True
    assert settings.parse.grok_timeout_ms == 100
    assert settings.integrity.enabled is True
    assert settings.integrity.batch_size == 1000
    assert settings.enrich.geoip_db_path is None
    assert settings.enrich.ioc_path is None
    assert settings.pipeline.worker_count == 4
    assert settings.pipeline.batch_size == 500
    assert settings.api.port == 8080


def test_get_settings_is_cached() -> None:
    """get_settings returns the same instance until the cache is cleared."""
    assert get_settings() is get_settings()


def test_env_override_scalar(monkeypatch: pytest.MonkeyPatch) -> None:
    """A prefixed, nested env var overrides the YAML value."""
    monkeypatch.setenv("ULPF_INGEST__SYSLOG_UDP_PORT", "1514")
    monkeypatch.setenv("ULPF_API__PORT", "9090")

    settings = Settings()

    assert settings.ingest.syslog_udp_port == 1514
    assert settings.api.port == 9090
    # Untouched values keep their YAML defaults.
    assert settings.ingest.syslog_tcp_port == 514


def test_env_override_bool_and_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Env overrides coerce to bool and Path types correctly."""
    monkeypatch.setenv("ULPF_PARSE__HOT_RELOAD", "false")
    monkeypatch.setenv("ULPF_ENRICH__GEOIP_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb")

    settings = Settings()

    assert settings.parse.hot_reload is False
    assert settings.enrich.geoip_db_path == Path("/opt/geoip/GeoLite2-City.mmdb")
