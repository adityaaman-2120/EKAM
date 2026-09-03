"""Ed25519 signatures over pipeline artefacts (batch Merkle roots, ledger heads,
lawful-export manifests).

WHY Ed25519 rather than RSA or ECDSA-P256:

* **Small, fixed sizes.** 32-byte public key, 64-byte signature, 32-byte private
  seed. Signing a batch root costs 64 extra bytes; a public key fits in a config
  value or a log line.
* **Fast.** Sign and verify are tens of microseconds — negligible next to
  hashing a batch — so ULPF can sign *every* batch root without thinking about
  cost.
* **No parameters to get wrong.** The curve (edwards25519), the hash (SHA-512),
  the point encoding, and the per-signature nonce are all fixed by the scheme.
  There is no curve to choose, no padding mode to pick (PKCS#1 v1.5 vs PSS), no
  "which SHA", and no dependence on RNG quality at signing time — the nonce is
  derived deterministically from the private key and the message. Misuse-
  resistant by construction.
* **Deterministic.** The same key and message always produce the same signature,
  so signatures are reproducible in tests and audits.

Key files are PEM: the private key as **unencrypted** PKCS#8
(``-----BEGIN PRIVATE KEY-----``) written owner-read/write only (mode 0600), and
the public key as SubjectPublicKeyInfo (``-----BEGIN PUBLIC KEY-----``). The
private key is protected by filesystem permissions and must stay out of version
control (see ``deploy/keys`` and ``.gitignore``); only the public key is
committed / distributed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PRIVATE_KEY_NAME = "ulpf_ed25519_private.pem"
PUBLIC_KEY_NAME = "ulpf_ed25519_public.pem"

_PRIVATE_FILE_MODE = 0o600  # owner read/write only


class KeyPaths(NamedTuple):
    """The two files :func:`generate_keypair` wrote."""

    private: Path
    public: Path


def generate_keypair(path: str | Path, *, overwrite: bool = False) -> KeyPaths:
    """Generate an Ed25519 keypair and write both keys as PEM under ``path``.

    Args:
        path: Directory to write into; created (with parents) if missing.
        overwrite: Replace an existing private key. Without it, an existing
            private key at the target raises :class:`FileExistsError` so a live
            key is never silently destroyed.

    Returns:
        The private and public key file paths.
    """
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / PRIVATE_KEY_NAME
    public_path = directory / PUBLIC_KEY_NAME
    if private_path.exists() and not overwrite:
        raise FileExistsError(
            f"{private_path} already exists; pass overwrite=True to replace it"
        )

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = _public_pem(key.public_key())

    _write_private(private_path, private_pem)
    public_path.write_bytes(public_pem)
    return KeyPaths(private=private_path, public=public_path)


class Signer:
    """Holds an Ed25519 private key and signs bytes with it."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        """Wrap an already-loaded :class:`Ed25519PrivateKey`."""
        self._key = private_key

    @classmethod
    def load(cls, private_key_path: str | Path) -> Signer:
        """Load a Signer from an unencrypted PEM private key file."""
        pem = Path(private_key_path).read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError(f"{private_key_path} is not an Ed25519 private key")
        return cls(key)

    def sign(self, data: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``data``."""
        return self._key.sign(data)

    def public_key_pem(self) -> bytes:
        """The matching public key as SubjectPublicKeyInfo PEM."""
        return _public_pem(self._key.public_key())

    def verifier(self) -> Verifier:
        """A :class:`Verifier` for this key's public half."""
        return Verifier(self._key.public_key())


class Verifier:
    """Holds an Ed25519 public key and checks signatures against it."""

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        """Wrap an already-loaded :class:`Ed25519PublicKey`."""
        self._key = public_key

    @classmethod
    def load(cls, public_key_path: str | Path) -> Verifier:
        """Load a Verifier from a PEM public key file."""
        pem = Path(public_key_path).read_bytes()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"{public_key_path} is not an Ed25519 public key")
        return cls(key)

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Return ``True`` iff ``signature`` is a valid Ed25519 signature of ``data``.

        A wrong key, tampered data, or a malformed / wrong-length signature all
        return ``False`` — this never raises for a bad signature.
        """
        try:
            self._key.verify(signature, data)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


def _public_pem(public_key: Ed25519PublicKey) -> bytes:
    """Serialize a public key to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _write_private(path: Path, data: bytes) -> None:
    """Write the private key, then restrict it to owner read/write where supported."""
    path.write_bytes(data)
    try:
        os.chmod(path, _PRIVATE_FILE_MODE)
    except (OSError, NotImplementedError):  # e.g. some Windows filesystems
        pass
