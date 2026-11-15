"""Tests for API security, streaming upload size limits, and path traversal protection."""
import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings

client = TestClient(app)


def test_path_traversal_filename_sanitized():
    """Uploaded filename with directory traversal '../../etc/passwd' must be sanitized."""
    traversal_filename = "../../../../etc/passwd.py"
    fake_content = io.BytesIO(b"def safe(): return True\n")
    response = client.post(
        "/api/reviews/upload",
        files={"file": (traversal_filename, fake_content, "text/plain")},
        data={"focus": "all"},
    )
    assert response.status_code == 200
    data = response.json()
    # File name must be sanitized to basename
    assert ".." not in data["filename"]
    assert "/" not in data["filename"]
    assert data["filename"] == "passwd.py"


def test_upload_oversized_file_rejected():
    """Uploads exceeding max_diff_size_bytes must be rejected with 422."""
    oversized_bytes = b"A" * (settings.max_diff_size_bytes + 2048)
    fake_file = io.BytesIO(oversized_bytes)
    response = client.post(
        "/api/reviews/upload",
        files={"file": ("large_code.py", fake_file, "text/plain")},
        data={"focus": "all"},
    )
    assert response.status_code == 422
    assert "exceeds maximum allowed size" in response.json()["detail"]


def test_invalid_review_id_rejected():
    """Requests for review IDs with traversal or special characters return 400."""
    response = client.get("/api/reviews/../../etc/passwd")
    assert response.status_code in (400, 404)
