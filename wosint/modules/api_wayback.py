"""Historical URLs from the Internet Archive.

Archived paths often reveal endpoints, parameters and files that are no longer
linked from the live site, which makes the Wayback CDX index a good source of
historical attack surface.
"""

from __future__ import annotations

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

CDX_URL = "https://web.archive.org/cdx/search/cdx"

#: Extensions worth calling out when they appear in the archive.
INTERESTING_SUFFIXES = (
    ".sql",
    ".bak",
    ".zip",
    ".tar.gz",
    ".env",
    ".log",
    ".config",
    ".json",
    ".xml",
    ".yml",
    ".yaml",
    ".git",
    ".pem",
    ".key",
)

#: How many archived URLs to surface as findings.
MAX_URLS = 150


@register
class WaybackModule(ApiModule):
    """Archived URLs and the domain's coverage window in the Wayback Machine."""

    name = "wayback"
    title = "Wayback Machine"
    description = "Historical URLs recorded by the Internet Archive."
    source_url = "https://web.archive.org"
    supported_types = frozenset({TargetType.DOMAIN, TargetType.URL, TargetType.EMAIL})
    default_enabled = False

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target.domain
        if not domain:
            return out

        rows = await get_json(
            ctx.client,
            CDX_URL,
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode",
                "collapse": "urlkey",
                "limit": str(MAX_URLS * 4),
            },
        )
        if not isinstance(rows, list) or len(rows) < 2:
            return out

        # The CDX API returns a header row followed by the data rows.
        records = [row for row in rows[1:] if isinstance(row, list) and len(row) >= 2]
        out.raw = "\n".join(f"{row[0]}\t{row[1]}" for row in records)

        timestamps = sorted(str(row[0]) for row in records if row[0])
        if timestamps:
            out.add(
                "archive",
                "Coverage",
                f"{_readable(timestamps[0])} to {_readable(timestamps[-1])}",
                f"{len(records)} archived snapshots",
            )

        for row in records[:MAX_URLS]:
            url = str(row[1])
            status = str(row[2]) if len(row) > 2 else ""
            severity = (
                Severity.NOTABLE if url.lower().endswith(INTERESTING_SUFFIXES) else Severity.INFO
            )
            out.add("archive", "Archived URL", url, f"HTTP {status}" if status else "", severity)
        return out


def _readable(timestamp: str) -> str:
    """Turn a CDX ``YYYYMMDDhhmmss`` stamp into ``YYYY-MM-DD``."""
    return (
        f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}" if len(timestamp) >= 8 else timestamp
    )
