"""Integration tests for the FastAPI app."""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

# We need to init the DB before importing app to avoid issues with lifespan
# Use TestClient which handles lifespan context automatically

SAMPLE_DIFF = """\
diff --git a/calculator.py b/calculator.py
index 1234567..abcdef0 100644
--- a/calculator.py
+++ b/calculator.py
@@ -1,3 +1,4 @@
 def add(a, b):
-    return a - b
+    return a + b
+
"""

MOCK_REVIEW_RESULT = {
    "summary": "Fixed arithmetic bug in add function.",
    "overall_status": "approved",
    "risk_level": "low",
    "files_reviewed": 1,
    "findings": [],
    "missing_tests": [],
    "positive_observations": ["Good fix"],
    "deterministic_findings": [],
    "llm_available": False,
}


@pytest.fixture(scope="module")
def client():
    """Create a test client with mocked LLM."""
    from app.schemas.findings import ReviewResult

    mock_result = ReviewResult(**MOCK_REVIEW_RESULT)

    with patch(
        "app.services.llm_service.call_ollama",
        new_callable=AsyncMock,
        side_effect=Exception("Ollama not available"),
    ):
        from app.main import app
        with TestClient(app) as c:
            yield c


def test_health_endpoint(client):
    """GET /api/health should return 200 with status ok."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "CodeLens AI"


def test_create_review_valid_diff(client):
    """POST /api/reviews with a valid diff should return 200."""
    response = client.post(
        "/api/reviews",
        json={"diff_content": SAMPLE_DIFF, "focus": "all"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
    assert "result" in data
    assert "processing_time_seconds" in data
    assert "created_at" in data


def test_create_review_empty_diff_returns_422(client):
    """POST /api/reviews with empty diff_content should return 422."""
    response = client.post(
        "/api/reviews",
        json={"diff_content": "", "focus": "all"},
    )
    assert response.status_code == 422


def test_create_review_unparseable_diff_returns_422(client):
    """POST /api/reviews with a diff that has no file changes should return 422."""
    response = client.post(
        "/api/reviews",
        json={"diff_content": "not a diff", "focus": "all"},
    )
    assert response.status_code == 422


def test_get_reviews_returns_list(client):
    """GET /api/reviews should return a list."""
    response = client.get("/api/reviews")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_get_review_by_id(client):
    """POST a review then GET it by ID."""
    post_resp = client.post(
        "/api/reviews",
        json={"diff_content": SAMPLE_DIFF, "focus": "all"},
    )
    assert post_resp.status_code == 200
    review_id = post_resp.json()["id"]

    get_resp = client.get(f"/api/reviews/{review_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == review_id


def test_get_nonexistent_review_returns_404(client):
    """GET /api/reviews/{id} with unknown id returns 404."""
    response = client.get("/api/reviews/nonexistent-id-12345")
    assert response.status_code == 404


def test_delete_review(client):
    """POST a review then DELETE it."""
    post_resp = client.post(
        "/api/reviews",
        json={"diff_content": SAMPLE_DIFF},
    )
    assert post_resp.status_code == 200
    review_id = post_resp.json()["id"]

    del_resp = client.delete(f"/api/reviews/{review_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True

    # Should now 404
    get_resp = client.get(f"/api/reviews/{review_id}")
    assert get_resp.status_code == 404
