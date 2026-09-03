"""``ulpf keys`` — manage the Ed25519 signing keypair.

``ulpf keys generate --out deploy/keys/`` writes ``ulpf_ed25519_private.pem``
(unencrypted PKCS#8, mode 0600) and ``ulpf_ed25519_public.pem``
(SubjectPublicKeyInfo). ``.gitignore`` keeps the private key out of the
repository and commits only the public key.
"""

from __future__ import annotations

from pathlib import Path

import typer

from ulpf.integrity.signing import generate_keypair

keys_app = typer.Typer(help="Ed25519 signing keys.", no_args_is_help=True)


@keys_app.command("generate")
def generate(
    out: Path = typer.Option(
        Path("deploy/keys"), "--out", help="Directory to write the PEM key files into."
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Replace an existing private key instead of failing."
    ),
) -> None:
    """Generate an Ed25519 keypair (private + public PEM) under ``--out``."""
    try:
        paths = generate_keypair(out, overwrite=overwrite)
    except FileExistsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"private key: {paths.private}  (keep this off version control)")
    typer.echo(f"public key : {paths.public}  (safe to commit / distribute)")
