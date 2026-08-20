"""Ready-made search links for a person, handle, address or number.

There is no keyless API that searches people, so the honest thing to offer is a
good set of starting points: the queries an analyst would type anyway, built
correctly and consistently.  Nothing is requested here -- the module only
assembles URLs, and following one is the analyst's decision.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote_plus

from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import LocalModule, ModuleOutput, RunContext

#: Engines that honour quoted phrases and the site: operator.
ENGINES = (
    ("Google", "https://www.google.com/search?q={query}"),
    ("Bing", "https://www.bing.com/search?q={query}"),
    ("DuckDuckGo", "https://duckduckgo.com/?q={query}"),
)

#: Platforms worth searching by name, with the site: filter that narrows to them.
SOCIAL_SITES = (
    ("LinkedIn", "linkedin.com/in"),
    ("Facebook", "facebook.com"),
    ("X / Twitter", "x.com"),
    ("Instagram", "instagram.com"),
    ("TikTok", "tiktok.com"),
    ("Reddit", "reddit.com"),
    ("GitHub", "github.com"),
)

#: Profile URLs that can be built directly from a handle.
HANDLE_URLS = (
    ("GitHub", "https://github.com/{handle}"),
    ("GitLab", "https://gitlab.com/{handle}"),
    ("Reddit", "https://www.reddit.com/user/{handle}"),
    ("X / Twitter", "https://x.com/{handle}"),
    ("Instagram", "https://www.instagram.com/{handle}/"),
    ("TikTok", "https://www.tiktok.com/@{handle}"),
    ("Telegram", "https://t.me/{handle}"),
    ("Keybase", "https://keybase.io/{handle}"),
    ("Medium", "https://medium.com/@{handle}"),
    ("Pastebin", "https://pastebin.com/u/{handle}"),
)


@register
class SearchLinkModule(LocalModule):
    """Search queries and candidate profile URLs, assembled locally."""

    name = "links"
    title = "Search links"
    description = "Ready-made search queries and profile URLs. Sends nothing itself."
    supported_types: ClassVar[frozenset] = frozenset(
        {TargetType.PERSON, TargetType.USERNAME, TargetType.EMAIL, TargetType.PHONE}
    )

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        phrase = f'"{target.value}"'

        for engine, template in ENGINES:
            out.add("search", engine, template.format(query=quote_plus(phrase)), "exact phrase")

        if target.type in (TargetType.PERSON, TargetType.EMAIL):
            for label, site in SOCIAL_SITES:
                query = quote_plus(f"{phrase} site:{site}")
                out.add("search", f"{label} search", ENGINES[0][1].format(query=query))

        if target.type is TargetType.USERNAME:
            for label, template in HANDLE_URLS:
                out.add(
                    "search",
                    f"{label} profile",
                    template.format(handle=target.value),
                    "candidate URL",
                )

        if target.type is TargetType.EMAIL:
            local_part = target.value.split("@", 1)[0]
            out.add(
                "search",
                "Handle search",
                ENGINES[0][1].format(query=quote_plus(f'"{local_part}"')),
                "the local part often doubles as a username elsewhere",
            )

        if target.type is TargetType.PHONE:
            for label, template in ENGINES:
                digits = target.value.lstrip("+")
                out.add(
                    "search",
                    f"{label} (digits only)",
                    template.format(query=quote_plus(f'"{digits}"')),
                    "some listings omit the country code",
                )

        out.raw = "\n".join(f"{f.label}\t{f.value}" for f in out.findings)
        return out
