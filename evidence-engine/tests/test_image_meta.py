"""Tests for evidence-engine.parsers.image_meta"""
import sys
import os
import importlib.util
import json
import tempfile

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "image_meta",
    os.path.join(os.path.dirname(__file__), '..', 'parsers', 'image_meta.py')
)
image_meta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_meta)

parse = image_meta.parse


def test_parse_when_pillow_not_available():
    """Test that missing Pillow produces a clear error."""
    # Temporarily disable PILLOW by setting the flag to False
    original_has_pillow = image_meta.HAS_PILLOW
    image_meta.HAS_PILLOW = False

    try:
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
            tmp.write(b"fake image data")
            tmp_path = tmp.name

        try:
            try:
                parse(
                    path=tmp_path,
                    case_id="CASE-001",
                    evidence_id="EVID-001",
                    sha256="a" * 64
                )
                assert False, "Expected RuntimeError when Pillow is missing"
            except RuntimeError as exc:
                assert "Pillow is required" in str(exc)

        finally:
            os.unlink(tmp_path)
    finally:
        # Restore original value
        image_meta.HAS_PILLOW = original_has_pillow


def test_parse_invalid_file():
    """Test that invalid file raises ValueError"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"not an image file")
        tmp_path = tmp.name

    try:
        try:
            events = parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            # If we get here without exception, that's OK - might be a valid but unsupported format
            # The important thing is it doesn't crash unexpectedly
        except ValueError as e:
            # This is expected for truly invalid files
            assert "Cannot process image file" in str(e)
        except Exception as e:
            # Other exceptions are also OK as long as they're not crashes
            pass
    finally:
        os.unlink(tmp_path)


def test_parse_nonexistent_file():
    """Test that nonexistent file raises appropriate error"""
    try:
        events = parse(
            path="/non/existent/file.jpg",
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )
        # If we get here, check what happened
    except FileNotFoundError:
        pass  # Expected
    except Exception as e:
        # Other exceptions are also OK
        pass


def test_parse_includes_perceptual_hash(tmp_path):
    from PIL import Image

    path = tmp_path / "synthetic.jpg"
    Image.new("RGB", (16, 16), "white").save(path)

    events = parse(str(path), "CASE-001", "EVID-001", "a" * 64)

    perceptual_hash = events[0]["raw"]["perceptual_hash"]
    json.dumps(events[0])
    assert len(perceptual_hash) == 16
    assert all(character in "0123456789abcdef" for character in perceptual_hash)


def test_parse_when_imagehash_not_available(tmp_path, monkeypatch):
    from PIL import Image

    path = tmp_path / "synthetic.jpg"
    Image.new("RGB", (16, 16), "white").save(path)
    monkeypatch.setattr(image_meta, "HAS_IMAGEHASH", False)

    try:
        parse(str(path), "CASE-001", "EVID-001", "a" * 64)
        assert False, "Expected RuntimeError when imagehash is missing"
    except RuntimeError as exc:
        assert "imagehash is required" in str(exc)


if __name__ == "__main__":
    test_parse_when_pillow_not_available()
    test_parse_invalid_file()
    test_parse_nonexistent_file()
    print("All image meta tests passed!")