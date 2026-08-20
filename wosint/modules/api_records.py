"""Public records: filings, court dockets, registries and sanctions lists.

These are records that exist precisely so they can be looked up -- securities
filings naming company officers, federal court dockets, corporate registries,
sanctions and PEP lists.  They are the most defensible sources in the whole
catalogue, and among the most useful for placing a name in a real institution.

Names are ambiguous in every one of them, so each module says how many other
matches it saw and marks its findings as inferred when the match rests on a name
alone.
"""

from __future__ import annotations

import json
from typing import ClassVar

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.settings import Settings
from ..core.targets import Target, TargetType
from .base import ApiModule, Availability, ModuleOutput, RunContext

SEC_SEARCH_URL = "https://efts.sec.gov/LATEST/search-index"
SEC_FILING_URL = "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"
COURTLISTENER_URL = "https://www.courtlistener.com/api/rest/v4/search/"
COURTLISTENER_WEB = "https://www.courtlistener.com"
OPENSANCTIONS_URL = "https://api.opensanctions.org/search/default"
OPENCORPORATES_URL = "https://api.opencorporates.com/v0.4/officers/search"

#: How many records each module will turn into findings.
MAX_RECORDS = 15


@register
class SecEdgarModule(ApiModule):
    """Company filings that mention a name or organisation.

    Being named in a filing places someone at a specific company on a specific
    date, which is a far stronger link than a social profile.
    """

    name = "sec"
    title = "SEC EDGAR filings"
    description = "US securities filings mentioning a name or company."
    source_url = "https://www.sec.gov/edgar"
    supported_types: ClassVar[frozenset] = frozenset(
        {TargetType.PERSON, TargetType.DOMAIN, TargetType.EMAIL}
    )
    default_enabled = False

    def availability(self, settings: Settings) -> Availability:
        base = super().availability(settings)
        if not base:
            return base
        # The SEC's access policy requires requests to identify a contact, and
        # sending a shared fake address on everyone's behalf would be both
        # dishonest and a good way to get the whole tool blocked.
        if not settings.contact_email:
            return Availability.missing(
                "the SEC requires a contact address (set WOSINT_CONTACT_EMAIL)"
            )
        return Availability.available()

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        query = _query_for(target)
        if not query:
            return out

        data = await get_json(
            ctx.client,
            SEC_SEARCH_URL,
            params={"q": f'"{query}"'},
            headers={"User-Agent": f"Wosint OSINT Research {ctx.settings.contact_email}"},
        )
        hits = (data.get("hits") or {}).get("hits") or []
        total = ((data.get("hits") or {}).get("total") or {}).get("value", len(hits))
        out.raw = json.dumps(data, indent=2)[:200_000]

        if not hits:
            return out

        out.add(
            "records",
            "SEC filings",
            f"{total} filing{'s' if total != 1 else ''} mention this name",
            "full-text search of EDGAR",
            Severity.NOTABLE,
        )

        seen_companies: set[str] = set()
        for hit in hits[:MAX_RECORDS]:
            source = hit.get("_source") or {}
            for display in source.get("display_names") or []:
                company = str(display)
                if company in seen_companies:
                    continue
                seen_companies.add(company)
                out.add(
                    "records",
                    "Named in filing by",
                    company,
                    f"{source.get('form', 'filing')} filed {source.get('file_date', '')}".strip(),
                    Severity.NOTABLE,
                    # A full-text hit on a name is not proof of identity.
                    inferred=target.type is TargetType.PERSON,
                )
            for cik in source.get("ciks") or []:
                out.add(
                    "records",
                    "Filer profile",
                    SEC_FILING_URL.format(cik=cik),
                    "EDGAR filing history",
                    inferred=target.type is TargetType.PERSON,
                )
        return out


@register
class CourtListenerModule(ApiModule):
    """Federal and state court dockets mentioning a name."""

    name = "courtlistener"
    title = "Court records (CourtListener)"
    description = "US federal and state court dockets mentioning a name."
    source_url = "https://www.courtlistener.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PERSON, TargetType.DOMAIN})
    default_enabled = False

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        query = _query_for(target)
        if not query:
            return out

        headers = {}
        token = ctx.api_key(self.name)
        if token:
            # A token only raises the rate limit; the endpoint is public.
            headers["Authorization"] = f"Token {token}"

        data = await get_json(
            ctx.client,
            COURTLISTENER_URL,
            params={"q": f'"{query}"', "type": "r"},
            headers=headers,
        )
        results = data.get("results") or []
        out.raw = json.dumps(data, indent=2)[:200_000]

        if not results:
            return out

        out.add(
            "records",
            "Court dockets",
            f"{data.get('count', len(results))} dockets mention this name",
            "names in a docket include parties, counsel and judges",
            Severity.NOTABLE,
        )

        for record in results[:MAX_RECORDS]:
            docket = str(record.get("caseName") or record.get("case_name_full") or "docket")
            url = record.get("docket_absolute_url") or ""
            out.add(
                "records",
                "Docket",
                docket,
                f"{record.get('court', '')} · {record.get('docketNumber', '')} · "
                f"filed {record.get('dateFiled', 'unknown')}".strip(" ·"),
                Severity.NOTABLE,
                inferred=True,
            )
            if url:
                out.add(
                    "records",
                    "Docket record",
                    f"{COURTLISTENER_WEB}{url}",
                    docket,
                    inferred=True,
                )
        return out


@register
class OpenSanctionsModule(ApiModule):
    """Sanctions, watchlist and politically-exposed-person entries."""

    name = "opensanctions"
    title = "Sanctions and PEP lists"
    description = "Sanctions, watchlist and PEP entries for a name. Needs an API key."
    source_url = "https://www.opensanctions.org"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PERSON, TargetType.DOMAIN})
    requires_key = True

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        query = _query_for(target)
        if not query:
            return out

        data = await get_json(
            ctx.client,
            OPENSANCTIONS_URL,
            params={"q": query, "limit": str(MAX_RECORDS)},
            headers={"Authorization": f"ApiKey {ctx.api_key(self.name) or ''}"},
        )
        results = data.get("results") or []
        out.raw = json.dumps(data, indent=2)[:200_000]

        if not results:
            out.add("records", "Sanctions", "no match", "not found on any screened list")
            return out

        for record in results:
            properties = record.get("properties") or {}
            name = str(record.get("caption") or "unknown")
            datasets = ", ".join(str(d) for d in record.get("datasets") or [])
            out.add(
                "records",
                "Listed person",
                name,
                f"{record.get('schema', '')} · {datasets}".strip(" ·"),
                Severity.WARNING,
                inferred=True,
            )
            for country in properties.get("country") or []:
                out.add("records", "Listed country", str(country), name, inferred=True)
            for birth in properties.get("birthDate") or []:
                out.add("records", "Date of birth", str(birth), name, inferred=True)
        return out


@register
class OpenCorporatesModule(ApiModule):
    """Company officerships from corporate registries."""

    name = "opencorporates"
    title = "Company officers (OpenCorporates)"
    description = "Directorships and officerships from corporate registries. Needs an API key."
    source_url = "https://opencorporates.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PERSON})
    requires_key = True

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        data = await get_json(
            ctx.client,
            OPENCORPORATES_URL,
            params={"q": target.value, "api_token": ctx.api_key(self.name) or ""},
        )
        officers = ((data.get("results") or {}).get("officers")) or []
        out.raw = json.dumps(data, indent=2)[:200_000]

        for entry in officers[:MAX_RECORDS]:
            officer = entry.get("officer") or {}
            company = (officer.get("company") or {}).get("name", "")
            out.add(
                "records",
                "Officer of",
                str(company),
                f"{officer.get('position', 'officer')} · {officer.get('jurisdiction_code', '')} · "
                f"from {officer.get('start_date') or 'unknown'}".strip(" ·"),
                Severity.NOTABLE,
                inferred=True,
            )
            if officer.get("opencorporates_url"):
                out.add(
                    "records",
                    "Officer record",
                    str(officer["opencorporates_url"]),
                    str(company),
                    inferred=True,
                )
        return out


def _query_for(target: Target) -> str:
    """The name or organisation to search these registries for."""
    if target.type is TargetType.PERSON:
        return target.value
    if target.type is TargetType.EMAIL:
        return (target.domain or "").split(".")[0]
    if target.type is TargetType.DOMAIN:
        return target.value.split(".")[0]
    return target.value
