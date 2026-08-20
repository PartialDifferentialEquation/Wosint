"""Phone number analysis, done entirely on this machine.

Google's libphonenumber metadata answers most of the useful questions about a
number -- which country it belongs to, roughly where it was allocated, which
carrier issued the range, and whether it is a mobile, landline or VoIP line --
without telling anyone that you asked.
"""

from __future__ import annotations

from typing import ClassVar

import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType, phone_digits
from .base import LocalModule, ModuleOutput, RunContext

#: libphonenumber's number types, in plain English.
NUMBER_TYPES = {
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "landline or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal number",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "universal access number",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
}

#: Line types worth drawing attention to, and why.
NOTABLE_TYPES = {
    "VoIP": "often used to obscure the holder's identity or location",
    "premium rate": "charges the caller a premium",
    "personal number": "forwards to a number that is not shown",
}


@register
class PhoneModule(LocalModule):
    """Country, region, carrier, line type and dialling formats for a number."""

    name = "phone"
    title = "Phone number analysis"
    description = "Country, region, carrier and line type, worked out offline."
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PHONE})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        region_hint = ctx.settings.phone_region or None
        digits = phone_digits(target.value)

        try:
            number = phonenumbers.parse(target.value, region_hint)
        except phonenumbers.NumberParseException as exc:
            if target.value.startswith("+") or region_hint:
                raise RuntimeError(f"could not parse the number: {exc}") from exc
            # A national number with no country code and no configured default
            # region is genuinely ambiguous; say so instead of guessing.
            out.add(
                "phone",
                "Country",
                "unknown",
                "no country code given and no default region configured (set WOSINT_PHONE_REGION)",
                Severity.NOTABLE,
            )
            out.add("phone", "Digits", digits)
            out.raw = f"unparsed national number: {digits}"
            return out

        self._describe(number, out)
        out.raw = self._raw_dump(number, out)
        return out

    def _describe(self, number: phonenumbers.PhoneNumber, out: ModuleOutput) -> None:
        valid = phonenumbers.is_valid_number(number)
        if not valid:
            out.add(
                "phone",
                "Validity",
                "not a valid number",
                "the digits do not match any allocated range in this country",
                Severity.WARNING,
            )
        else:
            out.add("phone", "Validity", "valid and allocated")

        region = phonenumbers.region_code_for_number(number)
        out.add("phone", "Country code", f"+{number.country_code}")
        out.add("phone", "Country", region or "unknown")

        location = geocoder.description_for_number(number, "en")
        out.add("phone", "Region", location, "approximate area the range covers")

        network = carrier.name_for_number(number, "en")
        out.add("phone", "Carrier", network, "carrier the range was allocated to")

        line_type = NUMBER_TYPES.get(phonenumbers.number_type(number), "")
        if line_type:
            note = NOTABLE_TYPES.get(line_type, "")
            out.add(
                "phone",
                "Line type",
                line_type,
                note,
                Severity.NOTABLE if note else Severity.INFO,
            )

        for zone in timezone.time_zones_for_number(number):
            # libphonenumber returns this placeholder for ranges it cannot
            # place, which is noise rather than a finding.
            if zone != "Etc/Unknown":
                out.add("phone", "Timezone", zone)

        out.add(
            "phone",
            "E.164",
            phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
            "canonical international form",
        )
        out.add(
            "phone",
            "National format",
            phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
            "how it is written locally",
        )

    @staticmethod
    def _raw_dump(number: phonenumbers.PhoneNumber, out: ModuleOutput) -> str:
        lines = [
            f"country_code: {number.country_code}",
            f"national_number: {number.national_number}",
        ]
        lines += [f"{f.label}: {f.value}" for f in out.findings]
        return "\n".join(lines)
