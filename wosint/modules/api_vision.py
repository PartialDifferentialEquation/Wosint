"""Reading an image with Gemini to find things that can be looked up.

An image is the one source that carries information no parser can reach: text on
a sign, a handle on a screenshot, a uniform, a skyline.  This module asks Gemini
to read those out as *linkable identifiers* -- strings that can be fed back into
the rest of Wosint -- rather than to describe the picture.

It does not identify people. The model is instructed not to name anyone from
their face and not to guess at protected characteristics, and the module extracts
no biometric data of any kind: what it links on is what the image says, not who
it shows. Face matching is the capability that turns an OSINT tool into a
surveillance one, and it is deliberately absent.
"""

from __future__ import annotations

import json
import mimetypes
import os
from pathlib import Path
from typing import Any, ClassVar

from ..core.models import Severity
from ..core.registry import register
from ..core.settings import Settings
from ..core.targets import Target, TargetType
from .base import ApiModule, Availability, ModuleOutput, RunContext

#: The model used for image analysis. Override with WOSINT_VISION_MODEL.
DEFAULT_MODEL = "gemini-3.1-pro-preview"

#: Environment variables the Google SDK itself reads, accepted here too so a key
#: configured the usual way just works.
SDK_KEY_VARIABLES = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

#: Image types the API accepts inline, mapped from what we detect locally.
SUPPORTED_MEDIA_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
)

#: Inline image data is capped by the request size limit; larger files need the
#: Files API, which is a different upload flow.
MAX_IMAGE_BYTES = 20 * 1024 * 1024

#: Finish reasons that mean the model stopped rather than answered, mapped to
#: what to tell the analyst.
BLOCKING_FINISH_REASONS = {
    "SAFETY": "safety filters",
    "PROHIBITED_CONTENT": "prohibited content",
    "IMAGE_SAFETY": "image safety filters",
    "SPII": "the image appears to contain sensitive personal information",
    "RECITATION": "recitation filters",
    "BLOCKLIST": "a blocked-term list",
}

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

#: What a photograph is being examined for. The analyst says which, because a
#: picture of a street and a picture of a person are read for different things
#: and asking for everything at once gets a worse answer than asking for one.
SUBJECTS = ("general", "location", "people")

BASE_PROMPT = """\
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

#: Extra direction per subject, appended to the base prompt.
SUBJECT_PROMPTS = {
    "general": "",
    "location": """\

This photograph is being examined to work out WHERE it was taken. Prioritise \
anything that narrows down a place, and put it in `locations` or `context`:

- street names, house numbers, postcodes, and the names of businesses that \
could be looked up in a directory
- the language and script of any signage, and any regional spelling
- road markings, kerb and line colours, which side traffic drives on, bollard \
and traffic-light styles, utility pole and pavement construction
- vehicle registration plate formats and colours -- the format only, do not \
report plate numbers
- architecture, building materials and roof styles typical of a region
- vegetation, terrain, and the position of the sun or shadows
- any visible landmark, skyline or distinctive structure

Say what you actually see. If the image does not support a place, say nothing \
rather than guessing at one.
""",
    "people": """\

This photograph contains people. Read it for identifiers AROUND them, never \
for who they are:

- name tags, badges, lanyards, ID cards, or a name written anywhere
- logos on clothing, uniforms, equipment or vehicles that indicate an employer, \
a team, a school or a membership
- anything legible on a screen they are holding or standing near
- event branding, seating, signage or backdrops that place the occasion

Do not identify anyone by their face, do not name anyone whose name is not \
written in the image, and do not describe or estimate any physical or personal \
characteristic of anyone shown. Leave `handles` and `text` empty rather than \
guessing at a person's identity.
""",
}


def prompt_for(subject: str) -> str:
    """The extraction prompt for a given photo subject."""
    return BASE_PROMPT + SUBJECT_PROMPTS.get(subject, "")


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
    """Identifiers read out of an image by Gemini."""

    name = "vision"
    title = "Image analysis (Gemini)"
    description = "Reads text, handles, signage and context out of an image. Needs an API key."
    source_url = "https://ai.google.dev"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.IMAGE})
    requires_key = True

    def availability(self, settings: Settings) -> Availability:
        base = super().availability(settings)
        if base:
            return base
        if _sdk_key():
            return Availability.available()
        return Availability.missing(
            "no API key configured (set WOSINT_KEY_VISION or GEMINI_API_KEY)"
        )

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.value)
        media_type, raw = _read_image(path)

        subject = target.hint if target.hint in SUBJECTS else "general"
        response = await self._ask(raw, media_type, subject, ctx)
        text = _usable_text(response)
        out.raw = text

        try:
            extracted = json.loads(text)
        except ValueError as exc:
            raise RuntimeError("the model did not return usable JSON") from exc

        self._to_findings(extracted, out)
        if not out.findings:
            out.add("image", "Analysis", "nothing legible to look up in this image")
        return out

    async def _ask(self, raw: bytes, media_type: str, subject: str, ctx: RunContext) -> Any:
        """Send the image and return the raw API response."""
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise RuntimeError("the google-genai package is not installed") from exc

        client = genai.Client(api_key=ctx.api_key(self.name) or _sdk_key())
        return await client.aio.models.generate_content(
            model=ctx.settings.vision_model or DEFAULT_MODEL,
            contents=[
                types.Part.from_bytes(data=raw, mime_type=media_type),
                prompt_for(subject),
            ],
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=RESPONSE_SCHEMA,
                max_output_tokens=8000,
            ),
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


def _sdk_key() -> str | None:
    """A key set the way the Google SDK expects, if there is one."""
    for variable in SDK_KEY_VARIABLES:
        value = os.environ.get(variable)
        if value:
            return value
    return None


def _usable_text(response: Any) -> str:
    """The response body, or a clear error explaining why there is none.

    A blocked request and an empty answer look similar from the outside, so
    each case is turned into its own message rather than a generic parse
    failure further down.

    Raises:
        RuntimeError: If the prompt or the response was blocked, the output was
            truncated, or nothing came back at all.
    """
    feedback = getattr(response, "prompt_feedback", None)
    block_reason = getattr(feedback, "block_reason", None)
    if block_reason:
        raise RuntimeError(f"the request was blocked before analysis ({_name(block_reason)})")

    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        raise RuntimeError("the model returned no response")

    finish_reason = _name(getattr(candidates[0], "finish_reason", None))
    if finish_reason in BLOCKING_FINISH_REASONS:
        raise RuntimeError(
            f"the model declined to analyse this image ({BLOCKING_FINISH_REASONS[finish_reason]})"
        )
    if finish_reason == "MAX_TOKENS":
        raise RuntimeError("the response was cut off before it was complete")

    text = getattr(response, "text", None)
    if not text:
        raise RuntimeError("the model returned an empty response")
    return text


def _name(value: Any) -> str:
    """The plain name of an SDK enum member, which may also arrive as a string."""
    return str(getattr(value, "name", value) or "")


def _read_image(path: Path) -> tuple[str, bytes]:
    """Read an image and its media type.

    Raises:
        RuntimeError: If the type is unsupported, or the file is unreadable or
            too large to send inline.
    """
    media_type, _ = mimetypes.guess_type(path.name)
    if media_type not in SUPPORTED_MEDIA_TYPES:
        raise RuntimeError(
            f"unsupported image type {media_type or path.suffix!r}; "
            "the API accepts JPEG, PNG, WebP, HEIC and HEIF"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"could not read {path.name}: {exc}") from exc
    if len(raw) > MAX_IMAGE_BYTES:
        raise RuntimeError(
            f"{path.name} is {len(raw) / 1e6:.1f} MB; images sent inline must be under 20 MB"
        )
    return media_type, raw
