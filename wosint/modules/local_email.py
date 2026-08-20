"""What an email address says about itself.

Plenty can be read off an address before contacting anything: whether it is a
role account rather than a person, whether the provider is a throwaway service,
and whether a sub-address is carrying a tag that reveals where it was handed
out.  This module does that reading locally.
"""

from __future__ import annotations

from typing import ClassVar

from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import LocalModule, ModuleOutput, RunContext

#: Local parts that belong to a function rather than a person. Findings about
#: these carry different weight: a role account is rarely one individual.
ROLE_ACCOUNTS = frozenset(
    {
        "abuse",
        "admin",
        "administrator",
        "billing",
        "contact",
        "help",
        "hello",
        "hostmaster",
        "info",
        "it",
        "mail",
        "marketing",
        "no-reply",
        "noc",
        "noreply",
        "office",
        "postmaster",
        "privacy",
        "root",
        "sales",
        "security",
        "support",
        "sysadmin",
        "team",
        "webmaster",
    }
)

#: Well-known free consumer providers.
FREE_PROVIDERS = frozenset(
    {
        "aol.com",
        "gmail.com",
        "gmx.com",
        "gmx.de",
        "hotmail.com",
        "icloud.com",
        "live.com",
        "mail.com",
        "mail.ru",
        "me.com",
        "outlook.com",
        "proton.me",
        "protonmail.com",
        "yahoo.com",
        "yandex.ru",
        "zoho.com",
    }
)

#: Disposable and burner mailbox providers.
DISPOSABLE_PROVIDERS = frozenset(
    {
        "10minutemail.com",
        "dispostable.com",
        "guerrillamail.com",
        "mailinator.com",
        "maildrop.cc",
        "sharklasers.com",
        "temp-mail.org",
        "tempmail.com",
        "throwawaymail.com",
        "trashmail.com",
        "yopmail.com",
    }
)

#: Providers whose selling point is that the mailbox is not linked to a name.
PRIVACY_PROVIDERS = frozenset({"proton.me", "protonmail.com", "tutanota.com", "tuta.io"})


@register
class EmailProfileModule(LocalModule):
    """Structure, provider class and sub-addressing tags in an address."""

    name = "email"
    title = "Email address profile"
    description = "Role, provider and sub-address analysis, done offline."
    supported_types: ClassVar[frozenset] = frozenset({TargetType.EMAIL})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        local_part, _, domain = target.value.partition("@")

        out.add("contact", "Local part", local_part)
        out.add("contact", "Domain", domain)

        base, tag = _split_subaddress(local_part)
        if tag:
            out.add(
                "contact",
                "Sub-address tag",
                tag,
                f"base mailbox is {base}@{domain}; the tag often names where the "
                "address was given out",
                Severity.NOTABLE,
            )

        if base.lower() in ROLE_ACCOUNTS:
            out.add(
                "contact",
                "Account type",
                "role account",
                "reaches a function or a team, not one identified person",
                Severity.NOTABLE,
            )
        else:
            out.add("contact", "Account type", "individual mailbox")

        self._classify_provider(domain, out)
        self._guess_name(base, domain, out)

        out.raw = "\n".join(f"{f.label}: {f.value}" for f in out.findings)
        return out

    def _classify_provider(self, domain: str, out: ModuleOutput) -> None:
        if domain in DISPOSABLE_PROVIDERS:
            out.add(
                "contact",
                "Provider",
                f"{domain} (disposable)",
                "throwaway mailbox service; the address is probably short-lived",
                Severity.WARNING,
            )
        elif domain in PRIVACY_PROVIDERS:
            out.add(
                "contact",
                "Provider",
                f"{domain} (privacy-focused)",
                "provider chosen for anonymity",
                Severity.NOTABLE,
            )
        elif domain in FREE_PROVIDERS:
            out.add("contact", "Provider", f"{domain} (free consumer provider)")
        else:
            out.add(
                "contact",
                "Provider",
                f"{domain} (self-hosted or corporate)",
                "the domain itself is worth scanning separately",
                Severity.NOTABLE,
            )

    def _guess_name(self, base: str, domain: str, out: ModuleOutput) -> None:
        """Read a probable person's name out of a structured local part.

        Corporate addresses are usually generated from a naming convention, so
        "jane.doe@" is a strong hint at both the person and the convention the
        rest of the organisation follows.
        """
        if base.lower() in ROLE_ACCOUNTS:
            return
        for separator in (".", "_", "-"):
            parts = [p for p in base.split(separator) if p]
            if len(parts) == 2 and all(p.isalpha() and len(p) > 1 for p in parts):
                out.add(
                    "contact",
                    "Probable name",
                    " ".join(p.capitalize() for p in parts),
                    f"inferred from the {separator!r}-separated local part; the "
                    f"convention is likely first{separator}last@{domain}",
                    Severity.NOTABLE,
                )
                return


def _split_subaddress(local_part: str) -> tuple[str, str]:
    """Split ``user+tag`` into its base mailbox and tag."""
    base, separator, tag = local_part.partition("+")
    return (base, tag) if separator else (local_part, "")
