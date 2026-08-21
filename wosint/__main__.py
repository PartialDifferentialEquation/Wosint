"""Entry point: ``python -m wosint`` or the ``wosint`` console script.

With no arguments the desktop application opens.  The ``scan`` and ``modules``
subcommands drive the same engine from a terminal, which is handy for scripting
and for machines without a display.
"""

from __future__ import annotations

import argparse
import logging
import sys

from . import __version__
from . import modules as _modules
from .core.settings import Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wosint",
        description="Desktop OSINT workbench. Runs with no arguments to open the GUI.",
    )
    parser.add_argument("--version", action="version", version=f"wosint {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")

    sub = parser.add_subparsers(dest="command")

    gui = sub.add_parser("gui", help="open the desktop application (default)")
    gui.set_defaults(command="gui")

    scan = sub.add_parser("scan", help="run a scan in the terminal")
    scan.add_argument("target", help="domain, IP address, URL, email address or username")
    scan.add_argument(
        "-m",
        "--module",
        action="append",
        dest="modules",
        metavar="NAME",
        help="run only this module; repeatable",
    )
    scan.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan.add_argument(
        "--timeout", type=float, metavar="SECONDS", help="per-module timeout override"
    )

    profile = sub.add_parser("profile", help="print a profile exported earlier")
    profile.add_argument("path", help="a JSON file written by File → Export profile")
    profile.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    sub.add_parser("modules", help="list the module catalogue and its availability")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Dispatch to the GUI or a terminal subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.command == "modules":
        from .cli import list_modules

        return list_modules(sys.stdout)

    if args.command == "profile":
        from .cli import show_profile

        return show_profile(args.path, as_json=args.json, stream=sys.stdout)

    if args.command == "scan":
        from .cli import run_scan

        settings = Settings.load()
        if args.timeout:
            settings.module_timeout = args.timeout
        return run_scan(
            args.target,
            modules=args.modules,
            as_json=args.json,
            stream=sys.stdout,
            settings=settings,
        )

    from .gui.app import run_app

    return run_app(sys.argv[:1])


if __name__ == "__main__":
    raise SystemExit(main())
