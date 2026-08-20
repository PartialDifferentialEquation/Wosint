"""Structured biography from Wikidata.

For anyone notable enough to have an entry, Wikidata is the single best public
record available without a key: it carries dates, employers, citizenship and --
usefully for correlation -- the person's own social handles, all as structured
claims with references rather than prose.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

API_URL = "https://www.wikidata.org/w/api.php"
ITEM_URL = "https://www.wikidata.org/wiki/{item}"

#: Wikidata properties worth reading, mapped to display labels. The handle
#: properties matter most here: they are self-declared, so they link a public
#: figure to accounts with far more confidence than a username guess.
PROPERTIES: dict[str, tuple[str, bool]] = {
    "P569": ("Date of birth", False),
    "P570": ("Date of death", False),
    "P27": ("Citizenship", True),
    "P19": ("Place of birth", True),
    "P106": ("Occupation", True),
    "P108": ("Employer", True),
    "P69": ("Educated at", True),
    "P39": ("Position held", True),
    "P856": ("Official website", False),
    "P2002": ("X / Twitter", False),
    "P2003": ("Instagram", False),
    "P2013": ("Facebook", False),
    "P2037": ("GitHub", False),
    "P6634": ("LinkedIn", False),
    "P3417": ("Quora", False),
}

#: Handle properties, whose values are usernames rather than free text.
HANDLE_PROPERTIES = frozenset({"P2002", "P2003", "P2013", "P2037", "P6634"})

#: Profile URL templates for the handle properties above.
HANDLE_URLS = {
    "P2002": "https://x.com/{handle}",
    "P2003": "https://www.instagram.com/{handle}/",
    "P2013": "https://www.facebook.com/{handle}",
    "P2037": "https://github.com/{handle}",
    "P6634": "https://www.linkedin.com/in/{handle}",
}


@register
class WikidataModule(ApiModule):
    """Biographical claims and self-declared accounts for a named person."""

    name = "wikidata"
    title = "Wikidata"
    description = "Structured biography and self-declared accounts for a public figure."
    source_url = "https://www.wikidata.org"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PERSON, TargetType.USERNAME})

    def _headers(self, ctx: RunContext) -> dict[str, str]:
        """Wikimedia's robot policy asks callers to identify themselves."""
        contact = (
            ctx.settings.contact_email or "https://github.com/PartialDifferentialEquation/Wosint"
        )
        return {"User-Agent": f"Wosint/0.1 ({contact})"}

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        headers = self._headers(ctx)

        search = await get_json(
            ctx.client,
            API_URL,
            params={
                "action": "wbsearchentities",
                "search": target.value,
                "language": "en",
                "format": "json",
                "limit": "5",
                "type": "item",
            },
            headers=headers,
        )
        matches = search.get("search") or []
        if not matches:
            out.raw = f"no Wikidata item for {target.value}"
            return out

        best = matches[0]
        item_id = str(best.get("id"))
        # More than one match means the name is shared; say so rather than
        # silently picking the most popular person with that name.
        ambiguous = len(matches) > 1

        entity_data = await get_json(
            ctx.client,
            API_URL,
            params={"action": "wbgetentities", "ids": item_id, "format": "json", "languages": "en"},
            headers=headers,
        )
        item = (entity_data.get("entities") or {}).get(item_id) or {}
        out.raw = json.dumps(item, indent=2, sort_keys=True)[:200_000]

        label = _label(item) or str(best.get("label") or target.value)
        description = str(best.get("description") or "")
        out.add(
            "records",
            "Wikidata item",
            f"{label} ({item_id})",
            description,
            Severity.NOTABLE,
            inferred=ambiguous,
        )
        out.add("records", "Wikidata page", ITEM_URL.format(item=item_id), description)
        if ambiguous:
            out.add(
                "records",
                "Name is shared",
                f"{len(matches)} Wikidata items match this name",
                "; ".join(
                    f"{m.get('label')} — {m.get('description', '')}".strip(" —")
                    for m in matches[:4]
                ),
                Severity.NOTABLE,
            )

        await self._read_claims(item, out, ctx, headers, inferred=ambiguous)
        return out

    async def _read_claims(
        self,
        item: dict[str, Any],
        out: ModuleOutput,
        ctx: RunContext,
        headers: dict[str, str],
        *,
        inferred: bool,
    ) -> None:
        claims = item.get("claims") or {}
        referenced: set[str] = set()

        for prop, (label, is_item) in PROPERTIES.items():
            for statement in claims.get(prop) or []:
                value = _claim_value(statement)
                if value is None:
                    continue
                if is_item and isinstance(value, str) and value.startswith("Q"):
                    referenced.add(value)
                    out.add("records", label, value, "Wikidata item", inferred=inferred)
                    continue

                out.add("records", label, str(value), "", Severity.INFO, inferred=inferred)
                if prop in HANDLE_PROPERTIES:
                    # A self-declared handle is strong evidence, so it is
                    # emitted as an account the correlator can pivot on.
                    out.add(
                        "account",
                        label,
                        HANDLE_URLS[prop].format(handle=value),
                        "self-declared on Wikidata",
                        Severity.NOTABLE,
                        inferred=inferred,
                    )

        if referenced:
            await self._resolve_labels(referenced, out, ctx, headers)

    async def _resolve_labels(
        self,
        item_ids: set[str],
        out: ModuleOutput,
        ctx: RunContext,
        headers: dict[str, str],
    ) -> None:
        """Replace referenced item ids with their English labels.

        Wikidata answers in item ids ("Q30"), which are useless in a report, so
        one extra call turns every referenced id into a readable name.
        """
        data = await get_json(
            ctx.client,
            API_URL,
            params={
                "action": "wbgetentities",
                "ids": "|".join(sorted(item_ids)[:50]),
                "props": "labels",
                "languages": "en",
                "format": "json",
            },
            headers=headers,
        )
        labels = {key: _label(value) for key, value in (data.get("entities") or {}).items()}
        for finding in out.findings:
            resolved = labels.get(finding.value)
            if resolved:
                # Findings are frozen, so the value is swapped by rebuilding it.
                index = out.findings.index(finding)
                out.findings[index] = type(finding)(
                    category=finding.category,
                    label=finding.label,
                    value=resolved,
                    detail=finding.detail,
                    severity=finding.severity,
                    inferred=finding.inferred,
                )


def _label(item: dict[str, Any]) -> str:
    labels = item.get("labels") or {}
    english = labels.get("en") or {}
    return str(english.get("value") or "")


def _claim_value(statement: dict[str, Any]) -> Any:
    """The usable value of one Wikidata statement, or ``None``."""
    snak = (statement.get("mainsnak") or {}).get("datavalue") or {}
    value = snak.get("value")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if "id" in value:
            return value["id"]
        if "time" in value:
            # Wikidata times look like "+1815-12-10T00:00:00Z".
            return str(value["time"]).lstrip("+")[:10]
    return None
