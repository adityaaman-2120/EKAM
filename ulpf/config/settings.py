"""Application settings for ULPF.

Settings load from ``configs/ulpf.yaml`` and may be overridden by environment
variables prefixed with ``ULPF_``. Nested sections use a double-underscore
delimiter, e.g. ``ULPF_INGEST__SYSLOG_UDP_PORT=1514``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_PATH = _REPO_ROOT / "configs" / "ulpf.yaml"
_RUNTIME_DIR = Path("data/runtime")


class IngestSettings(BaseModel):
    """Network listener ports and intake queue bounds."""

    syslog_udp_port: int = 514
    syslog_tcp_port: int = 514
    syslog_tls_port: int = 6514
    http_port: int = 8081
    http_max_body_bytes: int = 8 * 1024 * 1024
    queue_max_size: int = 100_000
    file_tail_paths: list[str] = Field(default_factory=list)


class StorageSettings(BaseModel):
    """Filesystem locations for pipeline output, all under ``data/runtime/``."""

    bronze_path: Path = _RUNTIME_DIR / "bronze"
    silver_path: Path = _RUNTIME_DIR / "silver"
    dlq_path: Path = _RUNTIME_DIR / "dlq"
    ledger_path: Path = _RUNTIME_DIR / "ledger"
    state_path: Path = _RUNTIME_DIR / "state"


class ParseSettings(BaseModel):
    """Parser onboarding directory and per-parse limits."""

    sources_dir: Path = Path("configs/sources")
    hot_reload: bool = True
    grok_timeout_ms: int = 100


class IntegritySettings(BaseModel):
    """Cryptographic integrity (hash chain / Merkle) batching controls."""

    enabled: bool = True
    batch_size: int = 1000
    batch_timeout_seconds: int = 10


class EnrichSettings(BaseModel):
    """Enrichment data sources; paths are optional when unavailable."""

    geoip_db_path: Path | None = None
    ioc_path: Path | None = None
    enabled: bool = True


class PipelineSettings(BaseModel):
    """Worker fan-out and batch sizing for the processing pipeline."""

    worker_count: int = 4
    batch_size: int = 500


class TlsSettings(BaseModel):
    """TLS material for the RFC 5425 syslog-over-TLS listener (port 6514)."""

    cert_path: Path | None = None
    key_path: Path | None = None
    client_ca_path: Path | None = None
    require_client_cert: bool = False
    minimum_version: str = "TLSv1_2"


class ApiSettings(BaseModel):
    """FastAPI bind address."""

    host: str = "0.0.0.0"
    port: int = 8080


class Settings(BaseSettings):
    """Root settings object aggregating every configuration section."""

    model_config = SettingsConfigDict(
        env_prefix="ULPF_",
        env_nested_delimiter="__",
        yaml_file=_CONFIG_PATH,
        extra="ignore",
    )

    ingest: IngestSettings = Field(default_factory=IngestSettings)
    tls: TlsSettings = Field(default_factory=TlsSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    parse: ParseSettings = Field(default_factory=ParseSettings)
    integrity: IntegritySettings = Field(default_factory=IntegritySettings)
    enrich: EnrichSettings = Field(default_factory=EnrichSettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order sources so env vars win over the YAML file, which wins over defaults."""
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide :class:`Settings`, built once and cached.

    Call ``get_settings.cache_clear()`` to force a reload (used by tests).
    """
    return Settings()
