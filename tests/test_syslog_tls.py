"""Tests for :mod:`ulpf.ingest.syslog_tls`.

Certificates are minted in-process with ``cryptography`` (already a project
dependency) so the test needs no ``openssl``/``bash``. They are the same shape
as ``deploy/certs/generate_dev_certs.sh`` produces for local development: a
self-signed CA and a CA-signed server cert with ``127.0.0.1`` in its SAN.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import ipaddress
import ssl
from pathlib import Path

import pytest

from ulpf.core.models import RawEvent
from ulpf.ingest.syslog_tls import (
    SyslogTlsListener,
    build_server_ssl_context,
    resolve_tls_version,
)


def _dev_certs(target: Path) -> dict[str, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def _rsa() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ca_key = _rsa()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ULPF Dev Local CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    srv_key = _rsa()
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths = {
        "ca": target / "ca.crt",
        "cert": target / "server.crt",
        "key": target / "server.key",
    }
    paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths["cert"].write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    paths["key"].write_bytes(
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return paths


async def test_tls_listener_receives_one_framed_message(tmp_path: Path) -> None:
    certs = _dev_certs(tmp_path)
    server_ctx = build_server_ssl_context(certs["cert"], certs["key"])

    got: list[RawEvent] = []
    done = asyncio.Event()

    async def on_event(event: RawEvent) -> None:
        got.append(event)
        done.set()

    listener = SyslogTlsListener(server_ctx, source_id="test-tls")
    await listener.start("127.0.0.1", 0, on_event)
    host, port = listener.sockname[0], listener.sockname[1]

    client_ctx = ssl.create_default_context(cafile=str(certs["ca"]))
    reader, writer = await asyncio.open_connection(
        host, port, ssl=client_ctx, server_hostname="127.0.0.1"
    )

    msg = b"<34>1 2003-10-11T22:14:15.003Z host app - - - tls hello over 6514"
    framed = f"{len(msg)} ".encode() + msg
    try:
        writer.write(framed)
        await writer.drain()
        await asyncio.wait_for(done.wait(), timeout=5.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await listener.stop()

    assert len(got) == 1
    assert got[0].raw == msg
    assert got[0].raw_hash == hashlib.sha256(msg).hexdigest()
    assert got[0].raw_len == len(msg)
    assert got[0].transport == "tls"
    assert got[0].peer == "127.0.0.1"
    assert got[0].source_id == "test-tls"


def test_build_context_defaults_to_tls_1_2(tmp_path: Path) -> None:
    certs = _dev_certs(tmp_path)
    ctx = build_server_ssl_context(certs["cert"], certs["key"])
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_NONE


def test_build_context_mutual_tls_and_min_version(tmp_path: Path) -> None:
    certs = _dev_certs(tmp_path)
    ctx = build_server_ssl_context(
        certs["cert"],
        certs["key"],
        client_ca_path=certs["ca"],
        require_client_cert=True,
        minimum_version=resolve_tls_version("1.3"),
    )
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_require_client_cert_without_ca_raises(tmp_path: Path) -> None:
    certs = _dev_certs(tmp_path)
    with pytest.raises(ValueError):
        build_server_ssl_context(certs["cert"], certs["key"], require_client_cert=True)


def test_resolve_tls_version_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        resolve_tls_version("SSLv3")
