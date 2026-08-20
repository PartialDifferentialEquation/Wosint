"""Email and host harvesting with ``theHarvester``.

theHarvester queries search engines and public datasets rather than the target
itself, so the results are passive even though the tool is run locally.
"""

from __future__ import annotations

import re

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
HOST_RE = re.compile(r"^([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::(\d{1,5}))?$", re.IGNORECASE)

#: Data sources used; these need no API key.
SOURCES = "bing,duckduckgo,crtsh,otx,rapiddns,urlscan"


@register
class TheHarvesterModule(CliModule):
    """Email addresses and hostnames gathered from public sources."""

    name = "theharvester"
    title = "theHarvester"
    description = "Emails and hostnames from search engines and public datasets."
    tool = "theHarvester"
    install_hint = "pipx install theHarvester"
    supported_types = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL})
    default_enabled = False

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        domain = target.domain or target.value
        return [self.tool, "-d", domain, "-b", SOURCES, "-l", "200"]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        domain = target.domain or target.value
        emails: set[str] = set()
        hosts: set[str] = set()

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("*", "[", "-")):
                continue
            for email in EMAIL_RE.findall(line):
                emails.add(email.lower())
                continue
            match = HOST_RE.match(line.split()[0]) if line.split() else None
            if match and match.group(1).lower().endswith(domain):
                hosts.add(match.group(1).lower())

        for email in sorted(emails):
            severity = Severity.NOTABLE if email.endswith(f"@{domain}") else Severity.INFO
            out.add("contact", "Email", email, severity=severity)
        for host in sorted(hosts - {domain}):
            out.add("dns", "Host", host)
        return out
