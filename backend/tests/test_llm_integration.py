"""
Phase 4: LLM Review Engine Audit, Error Handling, and Live Integration Tests.

Validates:
1. extract_json handles direct JSON, markdown code fences, and raw text.
2. Malformed or invalid JSON raises ValueError safely without crashing.
3. Offline or timed-out Ollama service degrades gracefully to partial_analysis=True and overall_status='needs_attention'.
4. Real integration test against live Ollama service if available; skipped if unavailable (never mocked).
"""
import pytest
import urllib.request
from app.config import settings
from app.services.llm_service import extract_json, generate_review
from app.schemas.findings import Finding, ReviewResult


def test_extract_json_direct():
    payload = '{"summary": "Test summary", "overall_status": "approved", "risk_level": "low"}'
    data = extract_json(payload)
    assert data["summary"] == "Test summary"
    assert data["overall_status"] == "approved"


def test_extract_json_markdown_fences():
    payload = """Here is your review:
```json
{
  "summary": "Fenced summary",
  "overall_status": "changes_requested",
  "risk_level": "high",
  "findings": []
}
```
Hope this helps!"""
    data = extract_json(payload)
    assert data["summary"] == "Fenced summary"
    assert data["risk_level"] == "high"


def test_extract_json_outermost_braces():
    payload = 'Preamble text before { "summary": "Braced review", "overall_status": "approved", "risk_level": "low" } trailing text'
    data = extract_json(payload)
    assert data["summary"] == "Braced review"


def test_extract_json_malformed_raises_valueerror():
    payload = "This is completely invalid text with no JSON objects at all."
    with pytest.raises(ValueError, match="Failed to extract valid JSON"):
        extract_json(payload)


@pytest.mark.asyncio
async def test_llm_offline_fallback_guarantees_partial_review():
    """When pointed to a non-existent port, generate_review must return partial_analysis=True and needs_attention."""
    original_url = settings.ollama_base_url
    try:
        settings.ollama_base_url = "http://localhost:59999"  # Non-existent port
        result, ok = await generate_review(
            code_sections={"test.py": "def foo(): pass"},
            focus="all",
            language="python",
        )
        assert ok is False
        assert result.llm_available is False
        assert result.partial_analysis is True
        assert result.overall_status == "needs_attention"
        assert result.risk_level == "medium"
    finally:
        settings.ollama_base_url = original_url


@pytest.mark.asyncio
async def test_live_ollama_integration_if_available():
    """
    Live semantic review integration test against local Ollama.
    Runs ONLY if local Ollama service is reachable. Skipped otherwise (never mocked).
    """
    ollama_online = False
    try:
        req = urllib.request.Request(f"{settings.ollama_base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            if resp.status == 200:
                ollama_online = True
    except Exception:
        ollama_online = False

    if not ollama_online:
        pytest.skip(f"Local Ollama service unreachable at {settings.ollama_base_url}. Live LLM integration skipped.")

    code_sections = {
        "db.py": """\
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()
"""
    }
    result, ok = await generate_review(
        code_sections=code_sections,
        focus="security",
        language="python",
    )
    assert ok is True
    assert result.llm_available is True
    assert result.partial_analysis is False
    assert isinstance(result, ReviewResult)
