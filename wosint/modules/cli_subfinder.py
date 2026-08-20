"""Passive subdomain enumeration with ``subfinder``.

subfinder aggregates dozens of passive sources in one pass, so it usually finds
more than crt.sh alone -- at the cost of needing to be installed locally.
"""

from __future__ import annotations

from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext


@register
class SubfinderModule(CliModule):
    """Subdomains from subfinder's aggregated passive sources."""

    name = "subfinder"
    title = "subfinder"
    description = "Passive subdomain enumeration across many aggregated sources."
    tool = "subfinder"
    install_hint = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    supported_types = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL})
    default_enabled = False

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        domain = target.domain or target.value
        return [self.tool, "-silent", "-all", "-timeout", "10", "-d", domain]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        domain = target.domain or target.value
        for line in sorted({line.strip().lower() for line in output.stdout.splitlines()}):
            if line and line.endswith(domain) and line != domain:
                out.add("dns", "Subdomain", line)
        return out
