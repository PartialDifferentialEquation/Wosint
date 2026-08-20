"""Breach exposure from Have I Been Pwned.

HIBP's breach endpoint needs a paid API key, so this module stays unavailable
until one is configured.  It is worth wiring up anyway: knowing which breaches
an address appears in tells you which old passwords and personal details are
already circulating.
"""

from __future__ import annotations

import json
from typing import ClassVar

from ..core.http import HttpError, get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"

#: Classes of leaked data that matter most when triaging an exposure.
SENSITIVE_CLASSES = frozenset(
    {
        "Passwords",
        "Password hints",
        "Security questions and answers",
        "Bank account numbers",
        "Credit cards",
        "Government issued IDs",
        "Partial credit card data",
        "Social security numbers",
        "Physical addresses",
    }
)


@register
class HibpModule(ApiModule):
    """Breaches an email address is known to appear in."""

    name = "hibp"
    title = "Have I Been Pwned"
    description = "Known breaches containing an email address. Needs an API key."
    source_url = "https://haveibeenpwned.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.EMAIL})
    requires_key = True

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        key = ctx.api_key(self.name)

        try:
            data = await get_json(
                ctx.client,
                BREACH_URL.format(account=target.value),
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": key or ""},
            )
        except HttpError as exc:
            if exc.is_not_found:
                # HIBP answers "not breached" with a 404, which is good news
                # rather than an error.
                out.add("breach", "Breaches", "none known", "not found in any HIBP breach")
                out.raw = "no breaches"
                return out
            raise

        if not isinstance(data, list):
            return out

        out.raw = json.dumps(data, indent=2, sort_keys=True)
        out.add(
            "breach",
            "Breaches",
            str(len(data)),
            "distinct breaches contain this address",
            Severity.WARNING if data else Severity.INFO,
        )

        for breach in data:
            if not isinstance(breach, dict):
                continue
            name = str(breach.get("Name") or "unknown")
            classes = [str(c) for c in breach.get("DataClasses") or []]
            leaked = sorted(set(classes) & SENSITIVE_CLASSES)
            detail = f"{breach.get('BreachDate', 'date unknown')}"
            if leaked:
                detail += f" · leaked {', '.join(leaked).lower()}"
            out.add(
                "breach",
                "Breach",
                name,
                detail,
                Severity.WARNING if leaked else Severity.NOTABLE,
            )
        return out
