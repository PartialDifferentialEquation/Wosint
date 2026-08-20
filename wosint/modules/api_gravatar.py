"""Gravatar profiles attached to an email address.

Gravatar is keyed by a hash of the address, so a hit confirms the address is
real and in use -- and many people fill the profile in with their name, location
and links to their other accounts without realising it is public.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, ClassVar

from ..core.http import HttpError, get_json, head_ok
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

PROFILE_URL = "https://gravatar.com/{hash}.json"
AVATAR_URL = "https://gravatar.com/avatar/{hash}"
#: "d=404" turns the default fallback image off, so the status tells us whether
#: an avatar was actually uploaded; "s=1" keeps the download to one pixel.
AVATAR_PROBE_URL = AVATAR_URL + "?d=404&s=1"


def gravatar_hash(email: str) -> str:
    """Gravatar's identifier for an address: MD5 of the trimmed, lower-cased form.

    MD5 is Gravatar's choice, not ours -- it is an index into their service
    here, never a security control.
    """
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


@register
class GravatarModule(ApiModule):
    """Public Gravatar profile, if the address has one."""

    name = "gravatar"
    title = "Gravatar profile"
    description = "Public profile and avatar attached to an email address."
    source_url = "https://gravatar.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.EMAIL})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        digest = gravatar_hash(target.value)

        try:
            data = await get_json(ctx.client, PROFILE_URL.format(hash=digest))
        except HttpError as exc:
            if not exc.is_not_found:
                raise
            # A 404 means no *public profile*, which is not the same as no
            # account: an avatar can exist behind a private profile, and its
            # presence still confirms the address is registered and in use.
            if await head_ok(ctx.client, AVATAR_PROBE_URL.format(hash=digest)):
                out.add(
                    "profile",
                    "Gravatar",
                    "avatar registered, profile not public",
                    "the address is registered with Gravatar",
                    Severity.NOTABLE,
                )
                out.add("profile", "Avatar", AVATAR_URL.format(hash=digest))
                out.raw = f"avatar present, no public profile for {digest}"
                return out

            out.add(
                "profile",
                "Gravatar",
                "no public profile",
                "the address has no Gravatar, or the profile is private",
            )
            out.raw = f"no profile for {digest}"
            return out

        entries = data.get("entry") if isinstance(data, dict) else None
        if not entries:
            return out

        entry = entries[0]
        out.raw = json.dumps(data, indent=2, sort_keys=True)

        out.add(
            "profile",
            "Gravatar",
            "public profile exists",
            "confirms the address is real and in use",
            Severity.NOTABLE,
        )
        out.add("profile", "Display name", _text(entry, "displayName"), severity=Severity.NOTABLE)
        out.add("profile", "Full name", _name(entry), severity=Severity.NOTABLE)
        out.add("profile", "Location", _text(entry, "currentLocation"), severity=Severity.NOTABLE)
        out.add("profile", "About", _text(entry, "aboutMe"))
        out.add("profile", "Avatar", AVATAR_URL.format(hash=digest))
        out.add("profile", "Profile URL", _text(entry, "profileUrl"))

        for account in entry.get("accounts") or []:
            if not isinstance(account, dict):
                continue
            service = str(account.get("shortname") or account.get("domain") or "account")
            out.add(
                "account",
                service.title(),
                str(account.get("url") or ""),
                "linked from the Gravatar profile",
                Severity.NOTABLE,
            )

        for url in entry.get("urls") or []:
            if isinstance(url, dict):
                out.add(
                    "profile",
                    "Linked site",
                    str(url.get("value") or ""),
                    str(url.get("title") or ""),
                )

        return out


def _text(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    return str(value).strip() if isinstance(value, str) else ""


def _name(entry: dict[str, Any]) -> str:
    name = entry.get("name")
    if isinstance(name, dict):
        formatted = name.get("formatted")
        if isinstance(formatted, str):
            return formatted.strip()
        parts = [name.get("givenName"), name.get("familyName")]
        return " ".join(p for p in parts if isinstance(p, str) and p.strip())
    return str(name).strip() if isinstance(name, str) else ""
