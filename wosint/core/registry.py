"""The module registry.

Modules register themselves at import time; :mod:`wosint.modules` imports every
implementation so that a single ``import wosint.modules`` populates the whole
catalogue.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from ..modules.base import Module
    from .targets import Target

_REGISTRY: dict[str, Module] = {}

M = TypeVar("M", bound=type)


def register(cls: M) -> M:
    """Class decorator that adds a module to the catalogue.

    Raises:
        ValueError: If two modules claim the same name, which would otherwise
            silently shadow one another.
    """
    instance = cls()
    if instance.name in _REGISTRY:
        raise ValueError(f"duplicate module name: {instance.name!r}")
    _REGISTRY[instance.name] = instance
    return cls


def all_modules() -> list[Module]:
    """Every registered module, ordered by kind then title for stable display."""
    return sorted(_REGISTRY.values(), key=lambda m: (m.kind, m.title))


def get_module(name: str) -> Module:
    """Look a module up by name.

    Raises:
        KeyError: If no module with that name is registered.
    """
    return _REGISTRY[name]


def modules_for(target: Target, *, names: Iterable[str] | None = None) -> list[Module]:
    """The modules that can run against ``target``.

    Args:
        target: The target being scanned.
        names: Optional restriction to these module names; unknown names are
            ignored so that a stale saved selection cannot break a scan.
    """
    wanted = set(names) if names is not None else None
    return [
        module
        for module in all_modules()
        if module.supports(target) and (wanted is None or module.name in wanted)
    ]


def clear_registry() -> None:
    """Empty the catalogue. Intended for tests."""
    _REGISTRY.clear()
