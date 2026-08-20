"""Metadata carried inside an image file.

Cameras and phones write far more into a photograph than most people realise:
where it was taken, when, on which device, and sometimes under whose name.  None
of it requires contacting anyone -- the file already has it -- which makes this
the first thing to look at and the only image module that runs offline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from PIL import ExifTags, Image, UnidentifiedImageError

from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import LocalModule, ModuleOutput, RunContext

#: EXIF tags worth reporting, mapped to display labels.
TAGS = {
    "Make": "Camera make",
    "Model": "Camera model",
    "LensModel": "Lens",
    "BodySerialNumber": "Camera serial",
    "LensSerialNumber": "Lens serial",
    "Software": "Software",
    "DateTimeOriginal": "Taken",
    "DateTimeDigitized": "Digitised",
    "Artist": "Artist",
    "Copyright": "Copyright",
    "ImageDescription": "Description",
    "UserComment": "Comment",
    "HostComputer": "Host computer",
    "OwnerName": "Owner",
}

#: Tags that name a person or a specific device, rather than describing the shot.
IDENTIFYING_TAGS = frozenset(
    {"Artist", "Copyright", "OwnerName", "BodySerialNumber", "LensSerialNumber", "HostComputer"}
)

MAP_URL = "https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"


@register
class ExifModule(LocalModule):
    """GPS position, timestamps, device and authorship from image metadata."""

    name = "exif"
    title = "Image metadata (EXIF)"
    description = "GPS, timestamps, camera and authorship read from the file itself."
    supported_types: ClassVar[frozenset] = frozenset({TargetType.IMAGE})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        path = Path(target.value)

        try:
            with Image.open(path) as image:
                out.add("image", "File", path.name, f"{image.format} {image.width}x{image.height}")
                exif = image.getexif()
        except UnidentifiedImageError as exc:
            raise RuntimeError(f"not a readable image: {path.name}") from exc
        except OSError as exc:
            raise RuntimeError(f"could not read {path.name}: {exc}") from exc

        if not exif:
            out.add(
                "image",
                "Metadata",
                "none present",
                "stripped by the platform it was shared on, or never written",
            )
            out.raw = "no EXIF data"
            return out

        readable = _readable_tags(exif)
        out.raw = "\n".join(f"{k}: {v}" for k, v in sorted(readable.items()))

        for tag, label in TAGS.items():
            value = readable.get(tag)
            if value is None:
                continue
            out.add(
                "image",
                label,
                str(value),
                "identifies the device or the person who made the file"
                if tag in IDENTIFYING_TAGS
                else "",
                Severity.NOTABLE if tag in IDENTIFYING_TAGS else Severity.INFO,
            )

        self._read_gps(exif, out)
        return out

    def _read_gps(self, exif: Any, out: ModuleOutput) -> None:
        """Turn the GPS block into coordinates and a map link.

        A position plus a timestamp places someone somewhere, which is the
        single most sensitive thing an image usually carries.
        """
        try:
            gps = exif.get_ifd(ExifTags.IFD.GPSInfo)
        except (AttributeError, KeyError, OSError):
            return
        if not gps:
            return

        named = {ExifTags.GPSTAGS.get(key, key): value for key, value in gps.items()}
        latitude = _coordinate(named.get("GPSLatitude"), named.get("GPSLatitudeRef"))
        longitude = _coordinate(named.get("GPSLongitude"), named.get("GPSLongitudeRef"))

        if latitude is None or longitude is None:
            return

        out.add(
            "image",
            "GPS position",
            f"{latitude:.6f}, {longitude:.6f}",
            "the photograph records where it was taken",
            Severity.WARNING,
        )
        out.add(
            "image",
            "Map",
            MAP_URL.format(lat=f"{latitude:.6f}", lon=f"{longitude:.6f}"),
            "position on OpenStreetMap",
        )

        altitude = named.get("GPSAltitude")
        if altitude is not None:
            out.add("image", "Altitude", f"{float(altitude):.0f} m")
        stamp = named.get("GPSDateStamp")
        if stamp:
            out.add("image", "GPS timestamp", str(stamp), "UTC, from the satellite fix")


def _readable_tags(exif: Any) -> dict[str, Any]:
    """Map numeric EXIF tag ids to their names, dropping unprintable values."""
    readable: dict[str, Any] = {}
    for tag_id, value in exif.items():
        name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", "replace").strip("\x00").strip()
            except Exception:
                continue
        if value in ("", None):
            continue
        readable[name] = value
    return readable


def _coordinate(value: Any, reference: Any) -> float | None:
    """Convert EXIF degrees/minutes/seconds into a signed decimal degree."""
    if not value or reference is None:
        return None
    try:
        degrees, minutes, seconds = (float(part) for part in value)
    except (TypeError, ValueError):
        return None
    decimal = degrees + minutes / 60 + seconds / 3600
    return -decimal if str(reference).upper() in ("S", "W") else decimal
