"""Role 1: parser for image metadata.

Extracts metadata from images using Pillow (PIL). Supported formats depend on
what Pillow can read.

The parser extracts:
- timestamp: From EXIF DateTimeOriginal, DateTimeDigitized, or DateTime (in order)
- GPS location: From EXIF GPSInfo if available, converted to decimal degrees
- device/camera metadata: Make, Model, Software from EXIF
- All EXIF data is preserved in the raw field

If no timestamp can be found in EXIF, the parser uses the file's modification
time as a deterministic fallback (required by the Event contract).

Each image becomes one Event with:
- source = "image"
- artifact_ref = "{filename}" (whole file, as images don't have rows/items)
- location = {"lat": float, "lon": float} when GPS is available
- raw = dictionary containing all available metadata
"""
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from parsers.timestamps import normalize_timestamp

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    HAS_IMAGEHASH = False


def _get_exif_data(image: Image.Image) -> Dict[str, Any]:
    """Extract EXIF data from PIL Image object."""
    exif_data = {}
    try:
        exif = image._getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                exif_data[tag] = value
    except AttributeError:
        pass  # No EXIF data
    return exif_data


def _get_gps_info(exif_data: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """Extract GPS information from EXIF data and convert to decimal degrees."""
    if not HAS_PILLOW or "GPSInfo" not in exif_data:
        return None

    gps_info = exif_data["GPSInfo"]
    gps_data = {}

    # Convert GPS tag IDs to human-readable names
    for key in list(gps_info.keys()):
        name = GPSTAGS.get(key, key)
        gps_data[name] = gps_info[key]

    # Extract latitude and longitude
    lat = None
    lon = None

    try:
        if "GPSLatitude" in gps_data and "GPSLatitudeRef" in gps_data:
            lat = _convert_to_degrees(gps_data["GPSLatitude"])
            if gps_data["GPSLatitudeRef"] != "N":
                lat = -lat

        if "GPSLongitude" in gps_data and "GPSLongitudeRef" in gps_data:
            lon = _convert_to_degrees(gps_data["GPSLongitude"])
            if gps_data["GPSLongitudeRef"] != "E":
                lon = -lon
    except (KeyError, IndexError, TypeError, ValueError):
        pass  # Invalid GPS data

    if lat is not None and lon is not None:
        return {"lat": lat, "lon": lon}

    return None


def _convert_to_degrees(value: Tuple) -> float:
    """Convert GPS coordinates to degrees float."""
    d, m, s = value
    return float(d) + float(m) / 60 + float(s) / 3600


def _get_timestamp_from_exif(exif_data: Dict[str, Any]) -> Optional[str]:
    """Extract timestamp from EXIF data in order of preference."""
    # Try these tags in order: DateTimeOriginal, DateTimeDigitized, DateTime
    for tag in ["DateTimeOriginal", "DateTimeDigitized", "DateTime"]:
        if tag in exif_data and exif_data[tag]:
            # Convert from "YYYY:MM:DD HH:MM:SS" to ISO format
            dt_str = str(exif_data[tag])
            try:
                # Replace first space with T and : with - in date part
                parts = dt_str.split(" ")
                if len(parts) == 2:
                    date_part = parts[0].replace(":", "-")
                    time_part = parts[1]
                    return normalize_timestamp(f"{date_part}T{time_part}Z")
            except (AttributeError, IndexError):
                pass  # Invalid format
    return None


def _get_device_info(exif_data: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Extract device/camera information from EXIF data."""
    return {
        "make": exif_data.get("Make"),
        "model": exif_data.get("Model"),
        "software": exif_data.get("Software")
    }


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> List[Dict[str, Any]]:
    """Parse image metadata and return Events.

    Args:
        path: Path to the image file
        case_id: Case identifier
        evidence_id: Evidence identifier
        sha256: SHA-256 hash of the source file

    Returns:
        List containing one Event dictionary conforming to contracts/event.schema.json
        (empty list if Pillow is not available or image cannot be processed)

    Raises:
        ValueError: For invalid image files or unsupported formats when Pillow is available
    """
    if not HAS_PILLOW:
        raise RuntimeError("Pillow is required to parse image EXIF metadata; install pillow")
    if not HAS_IMAGEHASH:
        raise RuntimeError("imagehash is required to compute image perceptual hashes; install imagehash")

    try:
        with Image.open(path) as image:
            # Verify it's a valid image by loading basic info
            image.verify()

        # Reopen for actual processing (verify() closes the file)
        with Image.open(path) as image:
            # Get basic image info
            exif_data = _get_exif_data(image)

            # Extract timestamp
            timestamp = _get_timestamp_from_exif(exif_data)
            if not timestamp:
                # Fallback to file modification time (deterministic)
                mtime = os.path.getmtime(path)
                dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
                timestamp = normalize_timestamp(dt.isoformat())

            # Extract GPS location
            location = _get_gps_info(exif_data)

            # Extract device info
            device_info = _get_device_info(exif_data)

            # Build artifact_ref (whole file for images)
            filename = path.split('/')[-1].split('\\')[-1]
            artifact_ref = filename

            # Build raw metadata (everything we found)
            raw = {
                "exif": exif_data,
                "filename": filename,
                "format": image.format,
                "mode": image.mode,
                "size": image.size,
                "perceptual_hash": str(imagehash.phash(image)),
            }

            # Build the event
            event = {
                "event_id": "EV-000001",  # Single event per image
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_ref": artifact_ref,
                "sha256": sha256,
                "timestamp": timestamp,
                "source": "image",
                "action": "image_captured",  # Generic action for images
                "raw": raw
            }

            # Add location if available
            if location:
                event["location"] = location

            # Add optional device fields if available
            if device_info["make"]:
                event["device"] = device_info["make"]
            if device_info["model"]:
                # If we already set device from make, we might want to combine or choose
                # For now, let's put model in device if make wasn't available, or create a combined field
                if not event.get("device"):
                    event["device"] = device_info["model"]
                else:
                    # Both available - could combine or prioritize
                    event["device"] = f"{device_info['make']} {device_info['model']}"

            return [event]

    except Exception as e:
        # If we can't open/process the image, raise a clear error
        raise ValueError(f"Cannot process image file: {e}")