"""Base classes every OSINT module builds on.

Three shapes cover everything Wosint does today:

* :class:`CliModule` shells out to a locally installed tool and parses its
  output.
* :class:`ApiModule` queries a public HTTP endpoint.
* :class:`LocalModule` works the target out on this machine and sends nothing
  anywhere.

All three produce the same :class:`~wosint.core.models.Finding` objects, so the
rest of the application never needs to care which kind it is looking at.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

import httpx

from ..core.models import Finding, Severity
from ..core.process import CommandOutput, run_command, tool_available
from ..core.settings import Settings
from ..core.targets import Target, TargetType


@dataclass(slots=True)
class RunContext:
    """Everything a module is handed when it runs."""

    settings: Settings
    client: httpx.AsyncClient
    timeout: float

    def api_key(self, module: str) -> str | None:
        return self.settings.api_key(module)


@dataclass(slots=True)
class ModuleOutput:
    """What a module returns: normalised findings plus the untouched output."""

    findings: list[Finding] = field(default_factory=list)
    raw: str = ""

    def add(
        self,
        category: str,
        label: str,
        value: str,
        detail: str = "",
        severity: Severity = Severity.INFO,
        inferred: bool = False,
    ) -> None:
        """Append a finding, ignoring blank values.

        Set ``inferred`` when the finding rests on a guess -- an identifier the
        module worked out rather than one the source confirmed.
        """
        value = (value or "").strip()
        if not value:
            return
        self.findings.append(
            Finding(
                category=category,
                label=label,
                value=value,
                detail=detail.strip(),
                severity=severity,
                inferred=inferred,
            )
        )


class Availability:
    """Whether a module can run right now, and why not if it cannot."""

    __slots__ = ("ok", "reason")

    def __init__(self, ok: bool, reason: str = "") -> None:
        self.ok = ok
        self.reason = reason

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.ok

    @classmethod
    def available(cls) -> Availability:
        return cls(True)

    @classmethod
    def missing(cls, reason: str) -> Availability:
        return cls(False, reason)


class Module(ABC):
    """Base class for every source of intelligence.

    Subclasses set the class-level metadata and implement :meth:`execute`.
    """

    name: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str] = ""
    kind: ClassVar[str] = "api"
    supported_types: ClassVar[frozenset[TargetType]] = frozenset()
    #: Whether the module is ticked by default in the GUI.
    default_enabled: ClassVar[bool] = True
    #: Shown in the UI so the analyst knows what leaves their machine.
    reaches_network: ClassVar[bool] = True

    def supports(self, target: Target) -> bool:
        """Whether this module knows what to do with ``target``."""
        return target.type in self.supported_types

    def availability(self, settings: Settings) -> Availability:
        """Whether the module's prerequisites are met."""
        if self.name in settings.disabled_modules:
            return Availability.missing("disabled in settings")
        return Availability.available()

    @abstractmethod
    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        """Gather intelligence about ``target``.

        Raises:
            Exception: Any failure is caught by the runner and recorded on the
                module's result rather than aborting the scan.
        """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name}>"


class CliModule(Module):
    """A module that wraps a locally installed command line tool."""

    kind: ClassVar[str] = "cli"
    #: The executable that must be present on ``PATH``.
    tool: ClassVar[str]
    #: Where to get it, shown when the tool is missing.
    install_hint: ClassVar[str] = ""

    def availability(self, settings: Settings) -> Availability:
        base = super().availability(settings)
        if not base:
            return base
        if not tool_available(self.tool):
            hint = f" -- install with: {self.install_hint}" if self.install_hint else ""
            return Availability.missing(f"{self.tool} not found on PATH{hint}")
        return Availability.available()

    @abstractmethod
    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        """The full argument list to execute, starting with :attr:`tool`."""

    @abstractmethod
    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        """Turn tool output into findings."""

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        output = await run_command(self.build_args(target, ctx), timeout=ctx.timeout)
        result = self.parse(output, target)
        if not result.raw:
            result.raw = output.text
        if not output.ok and not result.findings:
            raise RuntimeError(
                f"{self.tool} exited with code {output.returncode}: "
                f"{(output.stderr or output.stdout).strip()[:300] or 'no output'}"
            )
        return result


class LocalModule(Module):
    """A module that analyses the target without contacting anything.

    Phone number parsing and search-link building are pure computation. Marking
    them as local rather than lumping them in with the API modules is what lets
    the interface tell an analyst which modules leave the machine -- useful when
    the target is a person and every outbound query is a disclosure.
    """

    kind: ClassVar[str] = "local"
    reaches_network: ClassVar[bool] = False


class ApiModule(Module):
    """A module that queries a public HTTP API."""

    kind: ClassVar[str] = "api"
    #: Set when the endpoint needs a key from ``settings.api_keys``.
    requires_key: ClassVar[bool] = False
    #: Human-readable home of the data source, shown in the UI.
    source_url: ClassVar[str] = ""

    def availability(self, settings: Settings) -> Availability:
        base = super().availability(settings)
        if not base:
            return base
        if self.requires_key and not settings.api_key(self.name):
            return Availability.missing(
                f"no API key configured (set WOSINT_KEY_{self.name.upper()})"
            )
        return Availability.available()
