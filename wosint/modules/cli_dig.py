"""Local DNS resolution with ``dig``.

The DoH module answers the same questions without any local tooling; running
``dig`` as well is still useful because it shows what *this* machine's resolver
returns, which can differ inside a corporate network or a split-horizon setup.
"""

from __future__ import annotations

from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: Record types requested in a single dig invocation.
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")


@register
class DigModule(CliModule):
    """Records as seen by the system resolver."""

    name = "dig"
    title = "dig (system resolver)"
    description = "DNS records resolved by this machine's configured resolver."
    tool = "dig"
    install_hint = "apt install dnsutils / brew install bind"
    supported_types = frozenset(
        {TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL, TargetType.IPV4, TargetType.IPV6}
    )
    default_enabled = False

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        args = [self.tool, "+noall", "+answer", "+nocomments", "+timeout=5", "+tries=1"]
        if target.is_ip:
            return [*args, "-x", target.value]
        domain = target.domain or target.value
        for record_type in RECORD_TYPES:
            args += [domain, record_type]
        return args

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        seen: set[tuple[str, str]] = set()

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            # dig answer lines are: NAME  TTL  CLASS  TYPE  RDATA
            parts = line.split(None, 4)
            if len(parts) < 5 or parts[2] != "IN":
                continue
            record_type, value = parts[3], parts[4].strip()
            key = (record_type, value)
            if key in seen:
                continue
            seen.add(key)
            label = "PTR record" if record_type == "PTR" else f"{record_type} record"
            detail = f"TTL {parts[1]}s" if parts[1].isdigit() else ""
            out.add("dns", label, value.strip('"'), detail)
        return out
