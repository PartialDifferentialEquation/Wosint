"""Account discovery for an email address with ``holehe``.

holehe asks each supported site's password-reset or registration flow whether an
address is already known to it, which finds accounts that never appear in a
search engine.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: holehe marks a hit with "[+] site.com" and a miss with "[-]".
HIT_RE = re.compile(r"^\[\+\]\s*(\S+)")
#: Sites it could not check at all.
ERROR_RE = re.compile(r"^\[x\]\s*(\S+)")


@register
class HoleheModule(CliModule):
    """Sites where an email address already has an account."""

    name = "holehe"
    title = "holehe (email account search)"
    description = "Checks an email address against sites that leak registration status."
    tool = "holehe"
    install_hint = "pipx install holehe"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.EMAIL})

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        return [self.tool, "--only-used", "--no-color", "--", target.value]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        unchecked = 0

        for line in output.stdout.splitlines():
            line = line.strip()
            hit = HIT_RE.match(line)
            if hit:
                out.add(
                    "account",
                    hit.group(1).rstrip(":"),
                    "account exists",
                    f"{target.value} is registered here",
                    Severity.NOTABLE,
                )
                continue
            if ERROR_RE.match(line):
                unchecked += 1

        if out.findings:
            out.add(
                "account",
                "Accounts found",
                str(len(out.findings)),
                "sites where this address is already registered",
            )
        if unchecked:
            out.add(
                "meta",
                "Unchecked sites",
                str(unchecked),
                "holehe could not reach these; the result is incomplete",
            )
        return out
