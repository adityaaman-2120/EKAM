"""``ulpf keys`` — manage the Ed25519 signing keypair.

``ulpf keys generate --out deploy/keys/`` writes ``ulpf_ed25519_private.pem``
(unencrypted PKCS#8, mode 0600 on POSIX) and ``ulpf_ed25519_public.pem``
(SubjectPublicKeyInfo). ``.gitignore`` keeps the private key out of the
repository and commits only the public key.

After generating, it prints the exact ``configs/ulpf.yaml`` lines to wire the
keys into the integrity ledger, and — with ``--set-config`` (or an interactive
``y`` at the prompt) — writes them in for you.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import typer

from ulpf.integrity.signing import generate_keypair

keys_app = typer.Typer(help="Ed25519 signing keys.", no_args_is_help=True)

_CONFIG_PATH = Path("configs/ulpf.yaml")
_INTEGRITY_KEYS = ("signing_key_path", "public_key_path")


@keys_app.command("generate")
def generate(
    out: Path = typer.Option(
        Path("deploy/keys"), "--out", help="Directory to write the PEM key files into."
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Replace an existing private key instead of failing."
    ),
    config: Path = typer.Option(
        _CONFIG_PATH, "--config", help="Config file to update when wiring the keys in."
    ),
    set_config: bool = typer.Option(
        False, "--set-config", help="Write signing/public key paths into --config without asking."
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
    typer.echo("")
    typer.echo("To turn the integrity ledger ON, put these lines under `integrity:` in")
    typer.echo(f"{config}:")
    typer.echo(f"  signing_key_path: {_posix(paths.private)}")
    typer.echo(f"  public_key_path: {_posix(paths.public)}")

    if not config.is_file():
        return
    if not set_config:
        if not sys.stdin.isatty():
            typer.echo(f"(re-run with --set-config to write these into {config})")
            return
        if not typer.confirm(f"\nUpdate {config} with these paths now?", default=False):
            return
    if _write_config(config, paths.private, paths.public):
        typer.echo(f"updated {config}")
    else:
        wanted = "/".join(_INTEGRITY_KEYS)
        typer.echo(f"could not find integrity.{wanted} in {config}; edit it by hand", err=True)


def _posix(path: Path) -> str:
    """A forward-slash path, so the emitted config line is portable."""
    return path.as_posix()


def _write_config(config: Path, private: Path, public: Path) -> bool:
    """Replace the two ``integrity`` key paths in ``config`` in place. True on success."""
    text = config.read_text(encoding="utf-8")
    values = {"signing_key_path": _posix(private), "public_key_path": _posix(public)}
    changed = 0
    for key, value in values.items():
        text, n = re.subn(
            rf"(?m)^(?P<indent>\s+){key}:.*$", rf"\g<indent>{key}: {value}", text, count=1
        )
        changed += n
    if changed != len(values):
        return False
    config.write_text(text, encoding="utf-8")
    return True
