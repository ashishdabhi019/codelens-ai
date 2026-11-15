"""Tests for robust LLM offline handling and partial analysis reporting."""
import pytest
from unittest.mock import patch
import httpx
from app.services.llm_service import generate_review
from app.agents.code_review_agent import run_review
from app.schemas.review import ReviewRequest


@pytest.mark.asyncio
async def test_offline_ollama_returns_partial_analysis():
    """When Ollama is unreachable, generate_review marks partial_analysis=True and llm_available=False."""
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused")):
            result, success = await generate_review(
                code_sections={"app.py": "def foo(): pass"},
                files_reviewed=1,
            )
            assert success is False
            assert result.llm_available is False
            assert result.partial_analysis is True
            # Must NOT be approved
            assert result.overall_status != "approved"
            # Must NOT be low risk
            assert result.risk_level != "low"
            assert "partial" in result.summary.lower() or "offline" in result.summary.lower()


@pytest.mark.asyncio
async def test_end_to_end_review_with_offline_ollama_runs_ast():
    """End-to-end review with offline Ollama still flags deterministic AST vulnerabilities."""
    diff = """\
diff --git a/vuln.py b/vuln.py
--- /dev/null
+++ b/vuln.py
@@ -0,0 +1,3 @@
+def query_data(cursor, user_id):
+    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
+    return cursor.fetchall()
"""
    req = ReviewRequest(diff_content=diff, filename="vuln.py")
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused")):
        with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Connection refused")):
            res = await run_review(req)

            assert res.llm_available is False
            assert res.partial_analysis is True
            assert len(res.findings) >= 1
            assert any("SQL" in f.title for f in res.findings)
            assert res.overall_status == "changes_requested"
            assert res.risk_level == "critical"
