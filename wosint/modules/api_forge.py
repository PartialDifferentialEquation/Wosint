"""Public developer-platform profiles for a username.

GitHub and GitLab both expose a keyless user endpoint.  Developer profiles are
unusually rich for OSINT purposes: they routinely carry a real name, an
employer, a location and a personal site, all volunteered by the account holder.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from ..core.http import HttpError, get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

GITHUB_USER_URL = "https://api.github.com/users/{username}"
GITLAB_USER_URL = "https://gitlab.com/api/v4/users"


def username_of(target: Target) -> str:
    """The handle to look up: an email's local part is a good first guess."""
    if target.type is TargetType.EMAIL:
        return target.value.split("@", 1)[0]
    return target.value


@register
class GitHubUserModule(ApiModule):
    """GitHub profile, including the name and employer people volunteer."""

    name = "github"
    title = "GitHub profile"
    description = "Public GitHub account details for a username."
    source_url = "https://github.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.USERNAME, TargetType.EMAIL})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        username = username_of(target)

        try:
            data = await get_json(ctx.client, GITHUB_USER_URL.format(username=username))
        except HttpError as exc:
            if not exc.is_not_found:
                # A block, a rate limit or an outage is not the same answer as
                # "this account does not exist", and must not be reported as one.
                raise
            out.raw = f"no GitHub account named {username}"
            return out

        if not isinstance(data, dict) or not data.get("login"):
            return out

        out.raw = json.dumps(data, indent=2, sort_keys=True)
        out.add(
            "account",
            "GitHub",
            str(data.get("html_url") or ""),
            "account exists",
            Severity.NOTABLE,
        )
        for label, key, severity in (
            ("Name", "name", Severity.NOTABLE),
            ("Company", "company", Severity.NOTABLE),
            ("Location", "location", Severity.NOTABLE),
            ("Public email", "email", Severity.WARNING),
            ("Blog", "blog", Severity.INFO),
            ("Bio", "bio", Severity.INFO),
            ("Twitter", "twitter_username", Severity.NOTABLE),
        ):
            out.add("profile", label, _text(data, key), severity=severity)

        out.add("profile", "Joined", str(data.get("created_at") or "")[:10])
        out.add(
            "profile",
            "Public repositories",
            str(data.get("public_repos") or 0),
            f"{data.get('followers', 0)} followers",
        )
        return out


@register
class GitLabUserModule(ApiModule):
    """GitLab profile for a username."""

    name = "gitlab"
    title = "GitLab profile"
    description = "Public GitLab account details for a username."
    source_url = "https://gitlab.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.USERNAME, TargetType.EMAIL})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        username = username_of(target)

        data = await get_json(ctx.client, GITLAB_USER_URL, params={"username": username})
        if not isinstance(data, list) or not data:
            out.raw = f"no GitLab account named {username}"
            return out

        user = data[0]
        out.raw = json.dumps(data, indent=2, sort_keys=True)
        out.add(
            "account",
            "GitLab",
            str(user.get("web_url") or ""),
            "account exists",
            Severity.NOTABLE,
        )
        out.add("profile", "Name", _text(user, "name"), severity=Severity.NOTABLE)
        out.add("profile", "State", _text(user, "state"))
        return out


def _text(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    return str(value).strip() if isinstance(value, str) else ""
