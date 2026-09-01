"""``ulpf`` command-line entrypoint (Typer).

Commands:

* ``ulpf run``          — start every configured listener plus the pipeline.
* ``ulpf version``      — print the installed version.
* ``ulpf config show``  — print the effective merged configuration.
"""

from __future__ import annotations

import asyncio
import json
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

import typer
import yaml

from ulpf import __version__ as _FALLBACK_VERSION
from ulpf.config.settings import Settings, get_settings
from ulpf.core.logging import configure_logging
from ulpf.core.runtime import Runtime

app = typer.Typer(
    help="ULPF — Universal Log Pre-processing Framework.", no_args_is_help=True
)
config_app = typer.Typer(help="Inspect configuration.", no_args_is_help=True)
app.add_typer(config_app, name="config")


def _resolve_version() -> str:
    """Installed distribution version, falling back to the package constant."""
    try:
        return _pkg_version("ulpf")
    except PackageNotFoundError:
        return _FALLBACK_VERSION


@app.command()
def version() -> None:
    """Print the ULPF version."""
    typer.echo(f"ulpf {_resolve_version()}")


@app.command()
def run() -> None:
    """Start all configured listeners and the processing pipeline."""
    settings = get_settings()
    configure_logging("INFO")
    try:
        asyncio.run(_serve(settings))
    except KeyboardInterrupt:  # pragma: no cover - interactive Ctrl-C
        typer.echo("shutting down")


async def _serve(settings: Settings) -> None:
    """Run the assembled :class:`Runtime` until a signal stops it."""
    await Runtime(settings).serve(on_started=_print_banner)


def _print_banner(runtime: Runtime) -> None:
    """Report the bound listener ports once startup completes."""
    typer.echo(
        "ULPF listening - "
        f"syslog-udp:{runtime.udp_port} syslog-tcp:{runtime.tcp_port} "
        f"syslog-tls:{runtime.tls_port or 'off'} "
        f"http:{get_settings().ingest.http_port}"
    )


@config_app.command("show")
def config_show(
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of YAML."),
) -> None:
    """Print the effective merged configuration (YAML by default)."""
    data = get_settings().model_dump(mode="json")
    if as_json:
        typer.echo(json.dumps(data, indent=2))
    else:
        typer.echo(yaml.safe_dump(data, sort_keys=False, default_flow_style=False).rstrip())


if __name__ == "__main__":  # pragma: no cover
    app()
