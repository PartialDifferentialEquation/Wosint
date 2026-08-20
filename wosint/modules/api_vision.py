"""Reading an image with Claude to find things that can be looked up.

An image is the one source that carries information no parser can reach: text on
a sign, a handle on a screenshot, a uniform, a skyline.  This module asks Claude
to read those out as *linkable identifiers* -- strings that can be fed back into
the rest of Wosint -- rather than to describe the picture.

It does not identify people. Claude is instructed not to name anyone from their
face and not to guess at protected characteristics, and the module extracts no
biometric data of any kind: what it links on is what the image says, not who it
shows. Face matching is the capability that turns an OSINT tool into a
surveillance one, and it is deliberately absent.
"""

from __future__ import annotations

import base64
import json
import mimetypes
from pathlib import Path
from typing import Any, ClassVar

from ..core.models import Severity
from ..core.registry import register
from ..core.settings import Settings
from ..core.targets import Target, TargetType
from .base import ApiModule, Availability, ModuleOutput, RunContext

#: The model used for image analysis.
MODEL = "claude-opus-5"

#: Largest image the API accepts, before base64 expansion.
MAX_IMAGE_BYTES = 5 * 1024 * 1024

SYSTEM_PROMPT = """\
You are assisting an OSINT analyst who is working within an authorised \
investigation. Your job is to read an image for identifiers that can be looked \
up in other systems -- not to describe the picture, and not to speculate.

Report only what is legibly present in the image. Never guess.

Do NOT identify any person by their face, and do NOT name anyone unless their \
name is written in the image (on a badge, a caption, a screen, a document). Do \
not estimate age, ethnicity, religion, health, or any other protected \
characteristic of anyone shown. If asked to do any of this, return empty lists \
for the relevant fields; the analyst expects that and it is the correct answer.
"""

USER_PROMPT = """\
Extract every identifier from this image that could be searched for elsewhere.

- text: any legible text, verbatim, one entry per distinct block.
- handles: usernames, @mentions, profile names or URLs visible on any screen.
- organisations: company or institution names on signage, uniforms, vehicles, \
documents or products.
- locations: place names, street names, addresses, or a landmark you can \
identify with confidence from the image alone.
- devices: visible hardware, software or interfaces (phone model, OS, app, \
browser) that indicate what was used.
- context: short factual notes about setting, time of day or season that would \
help place the photograph.

Use an empty list for anything not present. Do not infer beyond the image.
"""

#: Schema the response is constrained to, so the output is parseable.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "text": {"type": "array", "items": {"type": "string"}},
        "handles": {"type": "array", "items": {"type": "string"}},
        "organisations": {"type": "array", "items": {"type": "string"}},
        "locations": {"type": "array", "items": {"type": "string"}},
        "devices": {"type": "array", "items": {"type": "string"}},
        "context": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["text", "handles", "organisations", "locations", "devices", "context"],
    "additionalProperties": False,
}

#: Each extracted field, with the category and severity it becomes.
FIELDS = (
    ("handles", "account", "Handle", Severity.NOTABLE),
    ("organisations", "records", "Organisation", Severity.NOTABLE),
    ("locations", "image", "Location", Severity.NOTABLE),
    ("text", "image", "Visible text", Severity.INFO),
    ("devices", "image", "Device", Severity.INFO),
    ("context", "image", "Context", Severity.INFO),
)


@register
class VisionModule(ApiModule):
    """Identifiers read out of an image by Claude."""

    name = "vision"
    title = "Image analysis (Claude)"
    description = "Reads text, handles, signage and context out of an image. Needs an API key."
    source_url = "https://www.anthropic.com"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.IMAGE})
    requires_key = True

    def availability(self, settings: Settings) -> Availability:
        base = super().availability(settings)
        if base:
            return base
        # The SDK also reads ANTHROPIC_API_KEY, so a key configured that way is
        # perfectly usable even though WOSINT_KEY_VISION is unset.
        import os

        if os.environ.get("ANTHROPIC_API_KEY"):
            return Availability.available()
        return Availability.missing(
            "no API key configured (set WOSINT_KEY_VISION or ANTHROPIC_API_KEY)"
        )

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.value)
        media_type, data = _encode(path)

        response = await self._ask(data, media_type, ctx)

        # A safety decline is an answer, not a crash: say which category and
        # let the analyst decide what to do with the image.
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            raise RuntimeError(f"the model declined to analyse this image ({category})")

        text = next((b.text for b in response.content if b.type == "text"), "")
        out.raw = text
        try:
            extracted = json.loads(text)
        except ValueError as exc:
            raise RuntimeError("the model did not return usable JSON") from exc

        self._to_findings(extracted, out)
        if not out.findings:
            out.add("image", "Analysis", "nothing legible to look up in this image")
        return out

    async def _ask(self, data: str, media_type: str, ctx: RunContext) -> Any:
        """Send the image and return the raw API response."""
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RuntimeError("the anthropic package is not installed") from exc

        key = ctx.api_key(self.name)
        client = AsyncAnthropic(api_key=key) if key else AsyncAnthropic()
        async with client:
            return await client.messages.create(
                model=MODEL,
                max_tokens=8000,
                system=SYSTEM_PROMPT,
                output_config={"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": media_type,
                                    "data": data,
                                },
                            },
                            {"type": "text", "text": USER_PROMPT},
                        ],
                    }
                ],
            )

    def _to_findings(self, extracted: dict[str, Any], out: ModuleOutput) -> None:
        for key, category, label, severity in FIELDS:
            for value in extracted.get(key) or []:
                if not isinstance(value, str):
                    continue
                out.add(
                    category,
                    label,
                    value,
                    "read from the image",
                    severity,
                    # Everything here is a model's reading of a picture. It is a
                    # lead worth checking, never a fact to build a chain on.
                    inferred=True,
                )


def _encode(path: Path) -> tuple[str, str]:
    """Read an image as base64 with its media type.

    Raises:
        RuntimeError: If the file is unreadable or too large to send.
    """
    media_type, _ = mimetypes.guess_type(path.name)
    if media_type not in ("image/jpeg", "image/png", "image/gif", "image/webp"):
        raise RuntimeError(
            f"unsupported image type {media_type or path.suffix!r}; "
            "the API accepts JPEG, PNG, GIF and WebP"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"could not read {path.name}: {exc}") from exc
    if len(raw) > MAX_IMAGE_BYTES:
        raise RuntimeError(f"{path.name} is {len(raw) / 1e6:.1f} MB; the API accepts up to 5 MB")
    return media_type, base64.standard_b64encode(raw).decode("ascii")
