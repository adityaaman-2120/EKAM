"""Tests for :mod:`ulpf.integrity.signing` and the ``ulpf keys generate`` command."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from typer.testing import CliRunner

from ulpf.cli.main import app
from ulpf.integrity.signing import (
    PRIVATE_KEY_NAME,
    PUBLIC_KEY_NAME,
    Signer,
    Verifier,
    generate_keypair,
)

_MSG = b"merkle-root:9f2c...batch-2026-09-04T00:00:00Z"


def _keypair(tmp_path: Path):  # noqa: ANN202
    return generate_keypair(tmp_path / "keys")


# --------------------------------------------------------------------------
# generate_keypair


def test_generate_keypair_writes_two_pem_files(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)

    assert paths.private.name == PRIVATE_KEY_NAME
    assert paths.public.name == PUBLIC_KEY_NAME
    assert paths.private.is_file() and paths.public.is_file()
    assert paths.private.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert paths.public.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")
def test_private_key_is_written_owner_only(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)
    mode = stat.S_IMODE(paths.private.stat().st_mode)
    assert mode == 0o600


def test_generate_keypair_refuses_to_clobber_without_overwrite(tmp_path: Path) -> None:
    first = _keypair(tmp_path)
    original = first.private.read_bytes()

    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path / "keys")
    assert first.private.read_bytes() == original  # untouched

    replaced = generate_keypair(tmp_path / "keys", overwrite=True)
    assert replaced.private.read_bytes() != original  # a fresh key


# --------------------------------------------------------------------------
# sign / verify


def test_sign_then_verify_roundtrips(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)
    signature = Signer.load(paths.private).sign(_MSG)

    assert len(signature) == 64
    assert Verifier.load(paths.public).verify(_MSG, signature) is True


def test_signatures_are_deterministic(tmp_path: Path) -> None:
    signer = Signer.load(_keypair(tmp_path).private)
    assert signer.sign(_MSG) == signer.sign(_MSG)


def test_verify_rejects_tampered_data(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)
    signature = Signer.load(paths.private).sign(_MSG)
    verifier = Verifier.load(paths.public)

    assert verifier.verify(_MSG + b"!", signature) is False
    assert verifier.verify(b"", signature) is False


def test_verify_rejects_a_tampered_signature(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)
    signature = bytearray(Signer.load(paths.private).sign(_MSG))
    signature[0] ^= 0x01
    assert Verifier.load(paths.public).verify(_MSG, bytes(signature)) is False


def test_verify_rejects_a_malformed_signature_without_raising(tmp_path: Path) -> None:
    verifier = Verifier.load(_keypair(tmp_path).public)
    assert verifier.verify(_MSG, b"too-short") is False
    assert verifier.verify(_MSG, b"\x00" * 64) is False


def test_verify_rejects_a_signature_from_a_different_key(tmp_path: Path) -> None:
    signer_a = Signer.load(generate_keypair(tmp_path / "a").private)
    verifier_b = Verifier.load(generate_keypair(tmp_path / "b").public)
    assert verifier_b.verify(_MSG, signer_a.sign(_MSG)) is False


def test_signer_exposes_its_matching_public_key(tmp_path: Path) -> None:
    paths = _keypair(tmp_path)
    signer = Signer.load(paths.private)

    assert signer.public_key_pem() == paths.public.read_bytes()
    assert signer.verifier().verify(_MSG, signer.sign(_MSG)) is True


# --------------------------------------------------------------------------
# key-type validation


def _write_rsa_keys(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = directory / "rsa_private.pem"
    pub = directory / "rsa_public.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return priv, pub


def test_loaders_reject_non_ed25519_keys(tmp_path: Path) -> None:
    rsa_priv, rsa_pub = _write_rsa_keys(tmp_path / "rsa")
    with pytest.raises(TypeError):
        Signer.load(rsa_priv)
    with pytest.raises(TypeError):
        Verifier.load(rsa_pub)


# --------------------------------------------------------------------------
# CLI: ulpf keys generate


def test_cli_keys_generate_writes_the_keypair(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "deploy" / "keys"

    result = runner.invoke(app, ["keys", "generate", "--out", str(out)])

    assert result.exit_code == 0, result.output
    assert (out / PRIVATE_KEY_NAME).is_file()
    assert (out / PUBLIC_KEY_NAME).is_file()
    assert "private key" in result.output and "public key" in result.output

    # a valid, usable keypair
    sig = Signer.load(out / PRIVATE_KEY_NAME).sign(_MSG)
    assert Verifier.load(out / PUBLIC_KEY_NAME).verify(_MSG, sig) is True


def test_cli_keys_generate_fails_cleanly_on_an_existing_key(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "keys"
    assert runner.invoke(app, ["keys", "generate", "--out", str(out)]).exit_code == 0

    clash = runner.invoke(app, ["keys", "generate", "--out", str(out)])
    assert clash.exit_code == 1
    assert "already exists" in clash.output

    forced = runner.invoke(app, ["keys", "generate", "--out", str(out), "--overwrite"])
    assert forced.exit_code == 0
