"""Entry points into public records that have no API.

Most public records are searchable by a human and by nobody else: property
rolls, company registries, professional licences and court portals are public
by law but rarely machine-readable, and the ones that are usually charge for it.

This module builds the correct search URL for each and stops there.  It sends
nothing, and every link is a place a person could have gone anyway -- what it
saves is knowing which registries exist and how each expects a name.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import quote_plus

from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import LocalModule, ModuleOutput, RunContext

#: Registries that take a person's name. Every entry must actually search for
#: the target: a portal link that ignores the query reads like a result and is
#: not one.
PERSON_REGISTRIES = (
    ("Company officers", "https://opencorporates.com/officers?q={q}", "directorships worldwide"),
    (
        "UK companies",
        "https://find-and-update.company-information.service.gov.uk/search/officers?q={q}",
        "Companies House officer search",
    ),
    (
        "SEC filings",
        "https://efts.sec.gov/LATEST/search-index?q=%22{q}%22",
        "US securities filings",
    ),
    ("US court dockets", "https://www.courtlistener.com/?q=%22{q}%22", "federal and state dockets"),
    (
        "UK court listings",
        "https://www.thegazette.co.uk/all-notices/notice?text={q}",
        "The Gazette: insolvency and probate notices",
    ),
    ("Patents", "https://patents.google.com/?inventor={q}", "named inventor"),
    ("Academic works", "https://openalex.org/works?search={q}", "papers and affiliations"),
    (
        "ORCID",
        "https://orcid.org/orcid-search/search?searchQuery={q}",
        "researcher identity and employers",
    ),
    ("Sanctions and PEPs", "https://www.opensanctions.org/search/?q={q}", "watchlist screening"),
    (
        "Charity trustees (UK)",
        "https://register-of-charities.charitycommission.gov.uk/en/charity-search?p_p_id=uk_gov_ccew_onereg_charitydetails_web_portlet_CharityDetailsPortlet&keywords={q}",
        "trusteeships",
    ),
    (
        "Obituaries and archives",
        "https://www.legacy.com/us/obituaries/search?keyword={q}",
        "family names and dates",
    ),
)

#: Registries that take a company or domain name.
ORGANISATION_REGISTRIES = (
    ("Company registry", "https://opencorporates.com/companies?q={q}", "worldwide registry search"),
    (
        "UK companies",
        "https://find-and-update.company-information.service.gov.uk/search?q={q}",
        "Companies House",
    ),
    (
        "SEC filings",
        "https://efts.sec.gov/LATEST/search-index?q=%22{q}%22",
        "US securities filings",
    ),
    (
        "Trademarks",
        "https://branddb.wipo.int/en/quicksearch?sort=score%20desc&q={q}",
        "WIPO global brand database",
    ),
    ("Court dockets", "https://www.courtlistener.com/?q=%22{q}%22", "litigation history"),
)


@register
class PublicRecordsModule(LocalModule):
    """Correctly-formed search URLs for registries without an API."""

    name = "records"
    title = "Public records search"
    description = "Entry points into registries that have no API. Sends nothing itself."
    supported_types: ClassVar[frozenset] = frozenset(
        {TargetType.PERSON, TargetType.DOMAIN, TargetType.EMAIL}
    )
    default_enabled = False

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()

        if target.type is TargetType.PERSON:
            registries = PERSON_REGISTRIES
            query = target.value
        else:
            registries = ORGANISATION_REGISTRIES
            domain = target.domain or target.value
            # The registrable name is the useful part; the TLD is not.
            query = domain.split(".")[0]

        for label, template, note in registries:
            out.add("records", label, template.format(q=quote_plus(query)), note)

        out.add(
            "records",
            "Searching for",
            query,
            "registries expect a legal name, which may differ from a display name",
        )
        out.raw = "\n".join(f"{f.label}\t{f.value}" for f in out.findings)
        return out
