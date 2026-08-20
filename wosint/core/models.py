"""Data models shared by the engine, the GUI and the CLI.

Modules produce :class:`Finding` objects rather than free-form text, which is
what lets results from a subprocess and results from a JSON API end up in the
same table.  The raw tool output is always kept alongside the findings so
nothing is hidden from the analyst.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .targets import Target


class Severity(str, Enum):
    """How much attention a finding deserves.

    This is deliberately about *notability*, not vulnerability: Wosint reports
    what is publicly observable and leaves exploitation judgements to the
    analyst.
    """

    INFO = "info"
    NOTABLE = "notable"
    WARNING = "warning"

    @property
    def rank(self) -> int:
        return {Severity.INFO: 0, Severity.NOTABLE: 1, Severity.WARNING: 2}[self]


class ModuleStatus(str, Enum):
    """Terminal (and in-flight) states for a single module run."""

    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    EMPTY = "empty"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self not in (ModuleStatus.PENDING, ModuleStatus.RUNNING)

    @property
    def label(self) -> str:
        return {
            ModuleStatus.PENDING: "Queued",
            ModuleStatus.RUNNING: "Running",
            ModuleStatus.OK: "Done",
            ModuleStatus.EMPTY: "No results",
            ModuleStatus.ERROR: "Error",
            ModuleStatus.TIMEOUT: "Timed out",
            ModuleStatus.UNAVAILABLE: "Not installed",
            ModuleStatus.SKIPPED: "Skipped",
            ModuleStatus.CANCELLED: "Cancelled",
        }[self]


@dataclass(frozen=True, slots=True)
class Finding:
    """A single normalised observation about a target.

    Attributes:
        category: Grouping key such as ``dns``, ``certificate`` or ``account``.
        label: What the value is, e.g. ``"A record"`` or ``"Registrar"``.
        value: The observation itself.
        detail: Optional supporting context shown next to the value.
        severity: Notability of the observation.
        inferred: Whether this rests on a guess rather than on the source
            actually saying so. A GitHub profile found by trying an email's
            local part as a handle describes *a* person, but not necessarily
            the one being investigated -- and correlation has to know the
            difference, or one common handle quietly merges two strangers into
            a single profile.
    """

    category: str
    label: str
    value: str
    detail: str = ""
    severity: Severity = Severity.INFO
    inferred: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "label": self.label,
            "value": self.value,
            "detail": self.detail,
            "severity": self.severity.value,
            "inferred": self.inferred,
        }


@dataclass(slots=True)
class ModuleResult:
    """The outcome of running one module against one target."""

    module: str
    title: str
    kind: str
    status: ModuleStatus = ModuleStatus.PENDING
    findings: list[Finding] = field(default_factory=list)
    raw: str = ""
    error: str = ""
    duration_ms: int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def succeeded(self) -> bool:
        return self.status in (ModuleStatus.OK, ModuleStatus.EMPTY)

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "title": self.title,
            "kind": self.kind,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "findings": [f.as_dict() for f in self.findings],
            "raw": self.raw,
        }


@dataclass(slots=True)
class Scan:
    """A target plus the results of every module run against it."""

    target: Target
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    results: dict[str, ModuleResult] = field(default_factory=dict)
    cancelled: bool = False

    @property
    def is_running(self) -> bool:
        return self.finished_at is None

    @property
    def duration_ms(self) -> int:
        end = self.finished_at if self.finished_at is not None else time.time()
        return int((end - self.started_at) * 1000)

    @property
    def findings(self) -> list[Finding]:
        """Every finding from every module, most notable first.

        Ordering is stable within a severity so that repeated renders of a
        partially complete scan do not shuffle rows under the user's cursor.
        """
        collected: list[Finding] = []
        for result in self.results.values():
            collected.extend(result.findings)
        return sorted(collected, key=lambda f: -f.severity.rank)

    @property
    def progress(self) -> tuple[int, int]:
        """``(completed, total)`` module counts."""
        total = len(self.results)
        done = sum(1 for r in self.results.values() if r.status.is_terminal)
        return done, total

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": {
                "value": self.target.value,
                "type": self.target.type.value,
                "raw": self.target.raw,
            },
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "cancelled": self.cancelled,
            "results": [r.as_dict() for r in self.results.values()],
        }
