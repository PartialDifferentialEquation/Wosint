"""Host and network intelligence from HackerTarget's free endpoints.

These endpoints return plain text rather than JSON and are rate limited for
anonymous callers, so the module degrades politely when the quota is reached.
"""

from __future__ import annotations

from ..core.http import HttpError, get_text
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/"
REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/"

#: A shared address can host thousands of domains; listing them all would bury
#: every other finding in the results table.
MAX_HOSTED_DOMAINS = 200

#: Substrings HackerTarget uses in its plain-text error responses.
ERROR_MARKERS = ("api count exceeded", "error", "no records found", "invalid")


@register
class HackerTargetModule(ApiModule):
    """Passive subdomain enumeration and reverse IP lookups."""

    name = "hackertarget"
    title = "HackerTarget host search"
    description = "Passive subdomain and reverse-IP lookups from api.hackertarget.com."
    source_url = "https://hackertarget.com"
    supported_types = frozenset(
        {TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL, TargetType.IPV4}
    )

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()

        if target.type is TargetType.IPV4:
            body = await get_text(ctx.client, REVERSE_IP_URL, params={"q": target.value})
            out.raw = body.strip()
            hosts = sorted(set(_usable_lines(body)))
            if len(hosts) > MAX_HOSTED_DOMAINS:
                out.add(
                    "network",
                    "Shared hosting",
                    f"{len(hosts)} domains resolve to {target.value}",
                    f"showing the first {MAX_HOSTED_DOMAINS}; see raw output for the rest",
                    Severity.NOTABLE,
                )
            for host in hosts[:MAX_HOSTED_DOMAINS]:
                out.add("network", "Hosted domain", host, f"shares {target.value}")
            return out

        domain = target.domain
        if not domain:
            return out

        try:
            body = await get_text(ctx.client, HOSTSEARCH_URL, params={"q": domain})
        except HttpError as exc:
            raise HttpError(f"host search failed: {exc}") from exc

        out.raw = body.strip()
        for line in _usable_lines(body):
            host, _, address = line.partition(",")
            if not address:
                continue
            out.add("dns", "Host", host.strip(), f"resolves to {address.strip()}")

        if not out.findings and "api count exceeded" in body.lower():
            out.add(
                "meta",
                "Rate limit",
                "HackerTarget daily quota exceeded",
                "retry later or configure an API key",
                Severity.NOTABLE,
            )
        return out


def _usable_lines(body: str) -> list[str]:
    """Strip blank lines and HackerTarget's plain-text error responses."""
    lines = []
    for line in body.splitlines():
        line = line.strip()
        if not line or any(marker in line.lower() for marker in ERROR_MARKERS):
            continue
        lines.append(line)
    return lines
