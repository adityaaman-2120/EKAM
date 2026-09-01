"""Parse-engine registry — the plug-and-play seam for new log sources.

Engines register themselves at import time by calling
``registry.register(MyEngine())`` (or using the ``@registry.engine`` class
decorator). Onboarding a new source is then: drop an engine module into
``ulpf/parse/engines/`` and reference it from a source YAML — no edits here.

The module-level ``registry`` is a deliberate shared singleton (the plugin
table); ``EngineRegistry`` itself carries no class-level state, so tests and
alternative wirings can create isolated instances.
"""

from __future__ import annotations

import importlib
import pkgutil

from ulpf.parse.engines.base import ParseEngine

_SKIP_MODULES = frozenset({"base", "util"})


class EngineRegistry:
    """A name -> :class:`ParseEngine` table."""

    def __init__(self) -> None:
        """Create an empty registry."""
        self._engines: dict[str, ParseEngine] = {}

    def register(self, engine: ParseEngine) -> None:
        """Add ``engine`` under ``engine.name``. Raises on a duplicate name."""
        name = engine.name
        if name in self._engines:
            raise ValueError(f"parse engine {name!r} is already registered")
        self._engines[name] = engine

    def engine(self, cls: type[ParseEngine]) -> type[ParseEngine]:
        """Class decorator: instantiate ``cls`` with no args and register it."""
        self.register(cls())
        return cls

    def get(self, name: str) -> ParseEngine:
        """Return the engine registered as ``name``. Raises ``KeyError`` if absent."""
        try:
            return self._engines[name]
        except KeyError:
            raise KeyError(f"no parse engine registered as {name!r}") from None

    def list_names(self) -> list[str]:
        """Return the registered engine names, sorted."""
        return sorted(self._engines)

    def load_engine_modules(self) -> None:
        """Import every engine module in ``ulpf.parse.engines`` so they self-register."""
        from ulpf.parse import engines

        for info in pkgutil.iter_modules(engines.__path__):
            if info.name in _SKIP_MODULES or info.name.startswith("_"):
                continue
            importlib.import_module(f"{engines.__name__}.{info.name}")


registry = EngineRegistry()
