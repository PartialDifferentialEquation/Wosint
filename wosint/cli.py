"""Headless command line interface.

The GUI is the main way to use Wosint, but being able to run the same engine
from a terminal makes it scriptable and keeps the core honest: anything the CLI
cannot do without Qt is a sign that logic has leaked into the widgets.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from .core.correlate import Investigation
from .core.entities import InvestigationError
from .core.models import ModuleStatus, Scan, Severity
from .core.registry import all_modules
from .core.runner import scan_target
from .core.settings import Settings
from .core.targets import TargetError, parse_target

#: ANSI colours, used only when the stream is a terminal.
COLOURS = {
    Severity.INFO: "\033[0m",
    Severity.NOTABLE: "\033[33m",
    Severity.WARNING: "\033[31m",
}
RESET = "\033[0m"


def list_modules(stream: TextIO) -> int:
    """Print the module catalogue with availability."""
    settings = Settings.load()
    for module in all_modules():
        availability = module.availability(settings)
        mark = "✓" if availability.ok else "✗"
        types = ", ".join(sorted(t.value for t in module.supported_types))
        print(f"{mark} {module.name:<14} {module.kind:<4} {module.title}", file=stream)
        print(f"    targets: {types}", file=stream)
        if not availability.ok:
            print(f"    unavailable: {availability.reason}", file=stream)
    return 0


def run_scan(
    target_value: str,
    *,
    modules: Iterable[str] | None,
    as_json: bool,
    stream: TextIO,
    settings: Settings | None = None,
) -> int:
    """Scan ``target_value`` and write the results to ``stream``.

    Returns:
        A process exit code: 0 on success, 1 if the target could not be parsed
        or no module was able to run.
    """
    try:
        target = parse_target(target_value)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    settings = settings or Settings.load()
    progress = None if as_json else _make_progress(stream)
    scan = asyncio.run(scan_target(target, settings=settings, modules=modules, on_update=progress))

    if as_json:
        json.dump(scan.as_dict(), stream, indent=2)
        stream.write("\n")
    else:
        _print_report(scan, stream)

    ran = any(r.status.is_terminal and r.succeeded for r in scan.results.values())
    return 0 if ran else 1


def show_profile(path: str, *, as_json: bool, stream: TextIO) -> int:
    """Print a profile exported from the GUI or from a previous run.

    Reading a saved investigation back without Qt is also the check that the
    correlator stayed where it belongs: if this needed a widget, the picture
    would live in the interface rather than in the engine.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: {path}: {exc}", file=sys.stderr)
        return 1

    try:
        investigation = Investigation.from_json(text)
    except InvestigationError as exc:
        print(f"error: {path}: {exc}", file=sys.stderr)
        return 1

    if as_json:
        json.dump(investigation.as_dict(), stream, indent=2)
        stream.write("\n")
        return 0

    _print_profile(investigation, stream)
    return 0


def _print_profile(investigation: Investigation, stream: TextIO) -> None:
    scanned = investigation.scanned
    print(
        f"\nProfile assembled from {len(scanned)} scan{'s' if len(scanned) != 1 else ''}"
        + (f": {', '.join(scanned)}" if scanned else ""),
        file=stream,
    )
    print("=" * 70, file=stream)

    for entity_type, entities in investigation.summary().items():
        print(f"\n[{entity_type.label.lower()}]", file=stream)
        for entity in entities:
            # `corroboration` already says "inferred, unconfirmed" for a guess,
            # which is the one thing that must not be missed on a printed line.
            print(
                f"  {entity.confidence:>4.0%}  {entity.display:<40} {entity.corroboration}",
                file=stream,
            )

    pivots = [p for p in investigation.pivots() if not p.scanned]
    if pivots:
        print("\n[follow next]", file=stream)
        for pivot in pivots:
            print(f"  {pivot.value:<40} {pivot.reason}", file=stream)

    total = len(investigation.entities)
    print(
        f"\n{total} entit{'ies' if total != 1 else 'y'} · "
        f"{len(investigation.relations)} connections · "
        f"{len(pivots)} lead{'s' if len(pivots) != 1 else ''} not yet scanned",
        file=stream,
    )


def _make_progress(stream: TextIO):
    def on_update(result) -> None:
        if result.status is ModuleStatus.RUNNING:
            print(f"  … {result.title}", file=stream, flush=True)
        elif result.status.is_terminal:
            note = f" — {result.error}" if result.error else ""
            print(
                f"  {result.status.label:<13} {result.title} "
                f"({result.finding_count} findings){note}",
                file=stream,
                flush=True,
            )

    return on_update


def _print_report(scan: Scan, stream: TextIO) -> None:
    colour = COLOURS if stream.isatty() else dict.fromkeys(Severity, "")
    reset = RESET if stream.isatty() else ""

    print(f"\n{scan.target.value} ({scan.target.type.label})", file=stream)
    print("=" * 70, file=stream)

    by_category: dict[str, list] = {}
    for finding in scan.findings:
        by_category.setdefault(finding.category, []).append(finding)

    for category in sorted(by_category):
        print(f"\n[{category}]", file=stream)
        for finding in by_category[category]:
            detail = f"  ({finding.detail})" if finding.detail else ""
            print(
                f"  {colour[finding.severity]}{finding.label:<20} {finding.value}{detail}{reset}",
                file=stream,
            )

    done, total = scan.progress
    print(
        f"\n{len(scan.findings)} findings · {done}/{total} modules · "
        f"{scan.duration_ms / 1000:.1f}s",
        file=stream,
    )
