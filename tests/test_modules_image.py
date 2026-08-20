"""Image modules: EXIF metadata offline, and Claude vision behind a key."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image
from PIL.ExifTags import GPS, IFD, Base
from PIL.TiffImagePlugin import IFDRational

from wosint.core.registry import get_module
from wosint.core.settings import Settings
from wosint.core.targets import TargetError, TargetType, detect_target_type, parse_target
from wosint.modules.api_vision import DEFAULT_MODEL, SYSTEM_PROMPT


def values(output, label: str) -> list[str]:
    return [f.value for f in output.findings if f.label == label]


def first(output, label: str):
    return next(f for f in output.findings if f.label == label)


def write_image(
    path: Path,
    *,
    tags: dict | None = None,
    latitude: tuple | None = None,
    longitude: tuple | None = None,
) -> Path:
    """Write a small JPEG carrying the requested EXIF."""
    image = Image.new("RGB", (32, 24), (90, 120, 160))
    exif = image.getexif()
    for tag, value in (tags or {}).items():
        exif[tag.value] = value
    if latitude and longitude:
        gps = exif.get_ifd(IFD.GPSInfo)
        degrees, minutes, seconds, ref = latitude
        gps[GPS.GPSLatitude.value] = (
            IFDRational(degrees),
            IFDRational(minutes),
            IFDRational(int(seconds * 100), 100),
        )
        gps[GPS.GPSLatitudeRef.value] = ref
        degrees, minutes, seconds, ref = longitude
        gps[GPS.GPSLongitude.value] = (
            IFDRational(degrees),
            IFDRational(minutes),
            IFDRational(int(seconds * 100), 100),
        )
        gps[GPS.GPSLongitudeRef.value] = ref
    image.save(path, exif=exif)
    return path


# -- the image target type ---------------------------------------------------


def test_an_existing_image_path_is_an_image_target(tmp_path: Path) -> None:
    path = write_image(tmp_path / "photo.jpg")
    assert detect_target_type(str(path)) is TargetType.IMAGE


def test_a_missing_image_file_is_reported_clearly(tmp_path: Path) -> None:
    with pytest.raises(TargetError, match="No such image file"):
        detect_target_type(str(tmp_path / "absent.jpg"))


def test_image_targets_are_treated_as_personal(tmp_path: Path) -> None:
    path = write_image(tmp_path / "photo.jpg")
    assert parse_target(str(path)).is_personal


def test_image_paths_are_resolved(tmp_path: Path) -> None:
    write_image(tmp_path / "photo.jpg")
    target = parse_target(f"{tmp_path}/./photo.jpg")
    assert target.value == str(tmp_path / "photo.jpg")


# -- EXIF --------------------------------------------------------------------


async def test_exif_reads_camera_and_authorship(tmp_path: Path, ctx) -> None:
    path = write_image(
        tmp_path / "photo.jpg",
        tags={
            Base.Make: "Canon",
            Base.Model: "EOS R5",
            Base.Artist: "Jane Doe",
            Base.DateTimeOriginal: "2024:06:01 14:23:11",
        },
    )
    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert values(output, "Camera make") == ["Canon"]
    assert values(output, "Camera model") == ["EOS R5"]
    assert values(output, "Taken") == ["2024:06:01 14:23:11"]


async def test_authorship_tags_are_flagged_as_identifying(tmp_path: Path, ctx) -> None:
    path = write_image(tmp_path / "photo.jpg", tags={Base.Artist: "Jane Doe"})
    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert "identifies the device or the person" in first(output, "Artist").detail


async def test_exif_decodes_gps_to_decimal_degrees(tmp_path: Path, ctx) -> None:
    path = write_image(
        tmp_path / "photo.jpg",
        latitude=(51, 30, 26.04, "N"),
        longitude=(0, 7, 39.0, "W"),
    )
    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert values(output, "GPS position") == ["51.507233, -0.127500"]
    assert "mlat=51.507233" in values(output, "Map")[0]


async def test_southern_and_eastern_hemispheres_get_the_right_signs(tmp_path: Path, ctx) -> None:
    path = write_image(
        tmp_path / "photo.jpg",
        latitude=(33, 51, 54.0, "S"),
        longitude=(151, 12, 36.0, "E"),
    )
    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert values(output, "GPS position") == ["-33.865000, 151.210000"]


async def test_a_recorded_position_is_a_warning(tmp_path: Path, ctx) -> None:
    """A position plus a timestamp places someone somewhere."""
    from wosint.core.models import Severity

    path = write_image(
        tmp_path / "photo.jpg", latitude=(51, 30, 26.04, "N"), longitude=(0, 7, 39.0, "W")
    )
    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert first(output, "GPS position").severity is Severity.WARNING


async def test_an_image_with_no_metadata_says_so(tmp_path: Path, ctx) -> None:
    path = tmp_path / "bare.png"
    Image.new("RGB", (8, 8)).save(path)

    output = await get_module("exif").execute(parse_target(str(path)), ctx)

    assert values(output, "Metadata") == ["none present"]


async def test_a_file_that_is_not_an_image_is_an_error(tmp_path: Path, ctx) -> None:
    path = tmp_path / "fake.jpg"
    path.write_text("this is not a JPEG")

    with pytest.raises(RuntimeError, match="not a readable image"):
        await get_module("exif").execute(parse_target(str(path)), ctx)


async def test_exif_module_sends_nothing() -> None:
    assert get_module("exif").reaches_network is False


# -- Gemini vision -----------------------------------------------------------

EXTRACTION = {
    "text": ["ACME LOGISTICS", "Unit 4, Bell Lane"],
    "handles": ["@janedoe"],
    "organisations": ["Acme Logistics"],
    "locations": ["Bell Lane, Manchester"],
    "devices": ["iPhone 14 Pro"],
    "context": ["daytime, industrial estate"],
}


class FakeModels:
    def __init__(self, holder: dict, recorder: dict) -> None:
        self._holder = holder
        self._recorder = recorder

    async def generate_content(self, **kwargs):
        self._recorder.update(kwargs)
        return self._holder["response"]


class FakeClient:
    """Stands in for genai.Client, recording the request it was given."""

    def __init__(self, holder: dict, recorder: dict, **kwargs) -> None:
        recorder["client_kwargs"] = kwargs
        self.aio = SimpleNamespace(models=FakeModels(holder, recorder))


def fake_response(
    text: str | None,
    *,
    finish_reason: str = "STOP",
    block_reason: str | None = None,
    candidates: bool = True,
):
    """Build a response shaped like the SDK's, including its enum-ish fields."""
    return SimpleNamespace(
        text=text,
        candidates=[SimpleNamespace(finish_reason=SimpleNamespace(name=finish_reason))]
        if candidates
        else [],
        prompt_feedback=SimpleNamespace(
            block_reason=SimpleNamespace(name=block_reason) if block_reason else None
        ),
    )


@pytest.fixture
def vision(monkeypatch):
    """Patch the SDK client and hand back the recorder for assertions."""
    recorder: dict = {}
    holder: dict = {"response": fake_response(json.dumps(EXTRACTION))}

    from google import genai

    monkeypatch.setattr(genai, "Client", lambda **kwargs: FakeClient(holder, recorder, **kwargs))
    return SimpleNamespace(recorder=recorder, holder=holder)


def test_vision_needs_a_key(monkeypatch) -> None:
    for variable in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    availability = get_module("vision").availability(Settings())

    assert not availability.ok
    assert "WOSINT_KEY_VISION" in availability.reason
    assert "GEMINI_API_KEY" in availability.reason


@pytest.mark.parametrize("variable", ["GEMINI_API_KEY", "GOOGLE_API_KEY"])
def test_vision_accepts_the_sdk_environment_variables(monkeypatch, variable: str) -> None:
    """A key set the usual SDK way is perfectly usable."""
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, "test-key")

    assert get_module("vision").availability(Settings()).ok


async def test_vision_extracts_linkable_identifiers(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    path = write_image(tmp_path / "photo.jpg")

    output = await get_module("vision").execute(parse_target(str(path)), ctx)

    assert values(output, "Handle") == ["@janedoe"]
    assert values(output, "Organisation") == ["Acme Logistics"]
    assert values(output, "Location") == ["Bell Lane, Manchester"]
    assert "ACME LOGISTICS" in values(output, "Visible text")


async def test_everything_read_from_an_image_is_marked_inferred(
    tmp_path: Path, ctx, vision
) -> None:
    """A model's reading of a picture is a lead, never a fact to chain on."""
    ctx.settings.api_keys["vision"] = "test-key"
    path = write_image(tmp_path / "photo.jpg")

    output = await get_module("vision").execute(parse_target(str(path)), ctx)

    assert output.findings
    assert all(f.inferred for f in output.findings)


async def test_vision_requests_the_configured_model_and_schema(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    path = write_image(tmp_path / "photo.jpg")

    await get_module("vision").execute(parse_target(str(path)), ctx)
    request = vision.recorder

    assert request["model"] == DEFAULT_MODEL
    assert request["config"].response_mime_type == "application/json"
    assert request["config"].response_schema is not None
    assert request["client_kwargs"]["api_key"] == "test-key"


async def test_the_model_can_be_overridden_in_settings(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    ctx.settings.vision_model = "gemini-3.1-flash-preview"
    path = write_image(tmp_path / "photo.jpg")

    await get_module("vision").execute(parse_target(str(path)), ctx)

    assert vision.recorder["model"] == "gemini-3.1-flash-preview"


async def test_vision_sends_the_image_bytes_with_its_media_type(
    tmp_path: Path, ctx, vision
) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    path = write_image(tmp_path / "photo.jpg")

    await get_module("vision").execute(parse_target(str(path)), ctx)
    image_part = vision.recorder["contents"][0]

    assert image_part.inline_data.mime_type == "image/jpeg"
    assert image_part.inline_data.data


def test_the_prompt_forbids_identifying_people_by_face() -> None:
    """The module links on what an image says, not on who it shows."""
    assert "NOT identify any person by their face" in SYSTEM_PROMPT
    assert "protected characteristic" in SYSTEM_PROMPT
    assert "Never guess" in SYSTEM_PROMPT


async def test_a_blocked_response_is_reported_rather_than_crashing(
    tmp_path: Path, ctx, vision
) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response(None, finish_reason="SAFETY")
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match=r"declined to analyse this image \(safety filters\)"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_an_image_blocked_for_personal_information_says_which(
    tmp_path: Path, ctx, vision
) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response(None, finish_reason="SPII")
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match="sensitive personal information"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_a_prompt_blocked_before_analysis_is_distinguished(
    tmp_path: Path, ctx, vision
) -> None:
    """Blocked-on-input and blocked-on-output are different answers."""
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response(None, block_reason="PROHIBITED_CONTENT")
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match=r"blocked before analysis \(PROHIBITED_CONTENT\)"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_a_truncated_response_is_not_reported_as_bad_json(
    tmp_path: Path, ctx, vision
) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response('{"text": ["half', finish_reason="MAX_TOKENS")
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match="cut off before it was complete"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_no_candidates_is_reported_clearly(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response(None, candidates=False)
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match="no response"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_unusable_output_is_an_error_not_a_silent_empty(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response("not json at all")
    path = write_image(tmp_path / "photo.jpg")

    with pytest.raises(RuntimeError, match="usable JSON"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_an_image_with_nothing_legible_says_so(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    vision.holder["response"] = fake_response(
        json.dumps(
            {
                "text": [],
                "handles": [],
                "organisations": [],
                "locations": [],
                "devices": [],
                "context": [],
            }
        )
    )
    path = write_image(tmp_path / "photo.jpg")

    output = await get_module("vision").execute(parse_target(str(path)), ctx)

    assert values(output, "Analysis") == ["nothing legible to look up in this image"]


async def test_an_oversized_image_is_refused_before_upload(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    path = tmp_path / "huge.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * (21 * 1024 * 1024))

    with pytest.raises(RuntimeError, match="under 20 MB"):
        await get_module("vision").execute(parse_target(str(path)), ctx)


async def test_an_unsupported_image_type_is_refused(tmp_path: Path, ctx, vision) -> None:
    ctx.settings.api_keys["vision"] = "test-key"
    path = tmp_path / "photo.tiff"
    Image.new("RGB", (8, 8)).save(path)

    with pytest.raises(RuntimeError, match="unsupported image type"):
        await get_module("vision").execute(parse_target(str(path)), ctx)
