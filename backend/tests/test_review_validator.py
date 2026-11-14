"""Tests for validate_and_merge."""
import pytest
from app.schemas.findings import Finding, ReviewResult
from app.tools.review_validator import validate_and_merge


def _make_finding(title: str, severity: str, file: str = "foo.py", line: int = 1) -> Finding:
    return Finding(
        title=title,
        category="security",
        severity=severity,
        file=file,
        line=line,
        description="desc",
        impact="impact",
        recommendation="fix it",
        confidence=1.0,
    )


def _base_llm_result(findings=None, risk_level="low", status="approved") -> ReviewResult:
    return ReviewResult(
        summary="Test summary",
        overall_status=status,
        risk_level=risk_level,
        files_reviewed=1,
        findings=findings or [],
        llm_available=True,
    )


def test_deduplication_same_finding():
    """Same (file, line, title prefix) from both sources should appear only once."""
    f1 = _make_finding("SQL Injection via f-string", "critical", "db.py", 10)
    f2 = _make_finding("SQL Injection via f-string", "critical", "db.py", 10)
    llm_result = _base_llm_result(findings=[f2])
    merged = validate_and_merge(llm_result, [f1])
    # Should deduplicate: only 1 instance
    assert len(merged.findings) == 1


def test_no_deduplication_different_lines():
    """Same title but different lines → both kept."""
    f1 = _make_finding("SQL Injection via f-string", "critical", "db.py", 5)
    f2 = _make_finding("SQL Injection via f-string", "critical", "db.py", 15)
    llm_result = _base_llm_result(findings=[f2])
    merged = validate_and_merge(llm_result, [f1])
    assert len(merged.findings) == 2


def test_severity_ordering():
    """Findings should be sorted: critical first, then high, medium, low."""
    f_low = _make_finding("Low Issue", "low")
    f_high = _make_finding("High Issue", "high", line=2)
    f_crit = _make_finding("Critical Issue", "critical", line=3)
    f_med = _make_finding("Medium Issue", "medium", line=4)
    llm_result = _base_llm_result(findings=[f_low, f_med])
    merged = validate_and_merge(llm_result, [f_high, f_crit])
    severities = [f.severity for f in merged.findings]
    assert severities[0] == "critical"
    assert severities[1] == "high"
    assert "medium" in severities
    assert "low" in severities


def test_risk_level_upgrade_to_critical():
    """If any finding is critical, risk_level must become critical."""
    f = _make_finding("Critical Bug", "critical")
    llm_result = _base_llm_result(risk_level="low")
    merged = validate_and_merge(llm_result, [f])
    assert merged.risk_level == "critical"


def test_risk_level_upgrade_to_high():
    """If highest severity is high, risk_level must become high."""
    f = _make_finding("High Issue", "high")
    llm_result = _base_llm_result(risk_level="low")
    merged = validate_and_merge(llm_result, [f])
    assert merged.risk_level == "high"


def test_no_findings_preserves_llm_status():
    """With no findings from either source, original LLM status is preserved."""
    llm_result = _base_llm_result(risk_level="low", status="approved")
    merged = validate_and_merge(llm_result, [])
    assert merged.overall_status == "approved"
    assert merged.risk_level == "low"


def test_any_findings_forces_changes_requested():
    """If merged findings exist, overall_status becomes changes_requested."""
    f = _make_finding("Some Issue", "medium")
    llm_result = _base_llm_result(status="approved")
    merged = validate_and_merge(llm_result, [f])
    assert merged.overall_status == "changes_requested"


def test_deterministic_findings_stored():
    """Deterministic findings should be stored in deterministic_findings field."""
    f = _make_finding("SQL Issue", "critical")
    llm_result = _base_llm_result()
    merged = validate_and_merge(llm_result, [f])
    assert len(merged.deterministic_findings) == 1
    assert merged.deterministic_findings[0].title == "SQL Issue"
