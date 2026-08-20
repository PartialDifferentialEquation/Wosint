"""Username enumeration with ``sherlock``.

Sherlock checks a username against hundreds of sites; Wosint runs it with a
per-site timeout so a handful of slow endpoints cannot stall the whole scan.
"""

from __future__ import annotations

import re

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: Sherlock prints hits as "[+] Site: https://..." and misses as "[-] Site:".
HIT_RE = re.compile(r"^\[\+\]\s*([^:]+):\s*(\S+)")


@register
class SherlockModule(CliModule):
    """Accounts registered with a username across social platforms."""

    name = "sherlock"
    title = "sherlock (username search)"
    description = "Looks for a username across hundreds of social platforms."
    tool = "sherlock"
    install_hint = "pipx install sherlock-project"
    supported_types = frozenset({TargetType.USERNAME, TargetType.EMAIL})

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        username = (
            target.value.split("@", 1)[0] if target.type is TargetType.EMAIL else target.value
        )
        return [
            self.tool,
            "--timeout",
            "10",
            "--print-found",
            "--no-color",
            "--",
            username,
        ]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        for line in output.stdout.splitlines():
            match = HIT_RE.match(line.strip())
            if not match:
                continue
            site, url = match.group(1).strip(), match.group(2).strip()
            out.add("account", site, url, "account exists", Severity.NOTABLE)

        if out.findings:
            out.add(
                "account",
                "Accounts found",
                str(len(out.findings)),
                f"across the sites sherlock checks for {target.value}",
            )
        return out
