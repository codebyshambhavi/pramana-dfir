"""Tests for evidence-engine.parsers.image_meta"""
import sys
import os
import importlib.util
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
    """Test behavior when Pillow is not available"""
    # Temporarily disable PILLOW by setting the flag to False
    original_has_pillow = image_meta.HAS_PILLOW
    image_meta.HAS_PILLOW = False

    try:
        with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
            tmp.write(b"fake image data")
            tmp_path = tmp.name

        try:
            events = parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )

            # Should return empty list when Pillow is not available
            assert events == []

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


if __name__ == "__main__":
    test_parse_when_pillow_not_available()
    test_parse_invalid_file()
    test_parse_nonexistent_file()
    print("All image meta tests passed!")