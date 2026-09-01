"""Asyncio syslog over TLS (RFC 5425), conventionally on TCP port 6514.

RFC 5425 is just RFC 6587 octet-counted / non-transparent framing carried inside
a TLS session, so this module reuses :func:`ulpf.ingest.syslog_tcp.read_frames`
and :class:`ulpf.ingest.syslog_tcp.FramedListenerBase` verbatim — the only
addition is the TLS handshake.

Supported, all sourced from configuration:

* server certificate + private key (PEM paths);
* optional client-certificate verification for **mutual TLS** — supply a CA
  bundle to trust, and choose whether a client cert is *required* or merely
  *verified when presented*;
* a configurable **minimum TLS version**, defaulting to TLS 1.2 (TLS 1.0/1.1 are
  refused).
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from ulpf.config.settings import Settings
from ulpf.ingest.syslog_tcp import _DEFAULT_MAX_FRAME, FramedListenerBase, OnEvent

_TLS_VERSIONS: dict[str, ssl.TLSVersion] = {
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
    "1.3": ssl.TLSVersion.TLSv1_3,
}


def resolve_tls_version(name: str) -> ssl.TLSVersion:
    """Map a config string (``"TLSv1_2"``, ``"1.3"``, ...) to an ``ssl.TLSVersion``."""
    try:
        return _TLS_VERSIONS[name]
    except KeyError:
        raise ValueError(f"unsupported minimum TLS version: {name!r}") from None


def build_server_ssl_context(
    cert_path: Path | str,
    key_path: Path | str,
    *,
    client_ca_path: Path | str | None = None,
    require_client_cert: bool = False,
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
) -> ssl.SSLContext:
    """Build a server-side :class:`ssl.SSLContext` for the TLS syslog listener.

    Args:
        cert_path: PEM server certificate (chain).
        key_path: PEM private key for ``cert_path``.
        client_ca_path: PEM CA bundle used to verify client certificates; enables
            mutual TLS when provided.
        require_client_cert: If true, a client must present a cert trusted by
            ``client_ca_path`` or the handshake fails. Ignored (with an error) if
            no ``client_ca_path`` is given.
        minimum_version: Lowest TLS version the server will negotiate.
    """
    if require_client_cert and client_ca_path is None:
        raise ValueError("require_client_cert=True needs client_ca_path")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = minimum_version
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    if client_ca_path is not None:
        context.load_verify_locations(cafile=str(client_ca_path))
        context.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
    return context


class SyslogTlsListener(FramedListenerBase):
    """TLS syslog server (RFC 5425) emitting one :class:`RawEvent` per frame."""

    transport = "tls"

    def __init__(
        self,
        ssl_context: ssl.SSLContext,
        source_id: str = "syslog-tls",
        *,
        max_frame_bytes: int = _DEFAULT_MAX_FRAME,
    ) -> None:
        """Create a listener that terminates TLS with ``ssl_context``."""
        super().__init__(source_id, max_frame_bytes=max_frame_bytes)
        self._ssl = ssl_context

    @classmethod
    def from_settings(cls, settings: Settings, source_id: str = "syslog-tls") -> SyslogTlsListener:
        """Construct from ``settings.tls`` (cert/key/CA/min-version)."""
        tls = settings.tls
        if tls.cert_path is None or tls.key_path is None:
            raise ValueError("tls.cert_path and tls.key_path must be configured")
        context = build_server_ssl_context(
            tls.cert_path,
            tls.key_path,
            client_ca_path=tls.client_ca_path,
            require_client_cert=tls.require_client_cert,
            minimum_version=resolve_tls_version(tls.minimum_version),
        )
        return cls(context, source_id=source_id)

    async def start(self, host: str, port: int, on_event: OnEvent) -> None:
        """Bind ``host:port`` (``port=0`` for ephemeral) and serve framed TLS connections."""
        self._on_event = on_event
        self._server = await asyncio.start_server(
            self._handle_client, host, port, ssl=self._ssl
        )
