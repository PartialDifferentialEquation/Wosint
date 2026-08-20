"""Shared fixtures.

Importing :mod:`wosint.modules` populates a process-wide registry, so tests
that register their own modules must put the real catalogue back afterwards.
"""

from __future__ import annotations

import httpx
import pytest

import wosint.modules
from wosint.core import registry
from wosint.core.settings import Settings
from wosint.modules.base import RunContext


@pytest.fixture
def isolated_registry():
    """Give a test an empty registry, restoring the real one afterwards."""
    saved = dict(registry._REGISTRY)
    registry.clear_registry()
    try:
        yield registry
    finally:
        registry._REGISTRY.clear()
        registry._REGISTRY.update(saved)


@pytest.fixture
def settings() -> Settings:
    """Fast, predictable settings for tests."""
    return Settings(module_timeout=5.0, max_concurrency=4, http_timeout=5.0)


@pytest.fixture
async def ctx(settings: Settings):
    """A :class:`RunContext` with a real client for respx to intercept."""
    async with httpx.AsyncClient(timeout=5.0) as client:
        yield RunContext(settings=settings, client=client, timeout=5.0)
