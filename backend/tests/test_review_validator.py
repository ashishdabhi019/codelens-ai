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


def test_duplicate_detection_different_titles_same_root_cause():
    """Different titles pointing to the same root cause on the same line must be merged."""
    f_det = _make_finding(
        title="Inverted discount calculation formula",
        severity="high",
        file="calc.py",
        line=3,
    )
    f_det.suggested_fix = "final_price = price * (1 - discount / 100)"
    f_llm = _make_finding(
        title="Incorrect Discount Calculation",
        severity="medium",
        file="calc.py",
        line=3,
    )
    f_llm.description = "Formula divides instead of multiplies, causing discount calculation error."

    llm_result = _base_llm_result(findings=[f_llm])
    merged = validate_and_merge(llm_result, [f_det])

    # Must be merged into 1 finding
    assert len(merged.findings) == 1
    # Must keep the highest severity
    assert merged.findings[0].severity == "high"
    # Must preserve the valid suggested fix
    assert merged.findings[0].suggested_fix == "final_price = price * (1 - discount / 100)"


def test_duplicate_detection_adjacent_lines_same_concept():
    """Adjacent lines addressing the same defect concept (e.g. empty list crash) must be merged."""
    f1 = _make_finding(
        title="Potential ZeroDivisionError on empty collection",
        severity="high",
        file="calc.py",
        line=9,
    )
    f2 = _make_finding(
        title="Crash on Empty List",
        severity="high",
        file="calc.py",
        line=8,
    )
    llm_result = _base_llm_result(findings=[f2])
    merged = validate_and_merge(llm_result, [f1])
    assert len(merged.findings) == 1


def test_invalid_suggested_fix_identical_to_buggy_code():
    """A suggested fix identical to the original buggy line must be rejected (set to None)."""
    from app.tools.diff_parser import parse_git_diff

    diff = (
        "diff --git a/calc.py b/calc.py\n"
        "--- /dev/null\n"
        "+++ b/calc.py\n"
        "@@ -0,0 +1,5 @@\n"
        "+def discount(p, d):\n"
        "+    return p / (1 - d / 100)\n"
    )
    diff_files = parse_git_diff(diff)

    f = _make_finding("Inverted discount", "high", file="calc.py", line=2)
    # Returning the exact buggy line
    f.suggested_fix = "return p / (1 - d / 100)"

    llm_result = _base_llm_result(findings=[f])
    merged = validate_and_merge(llm_result, [], diff_files=diff_files)

    assert len(merged.findings) == 1
    # Fix must be rejected because it is identical to buggy code
    assert merged.findings[0].suggested_fix is None
    assert "identical or equivalent" in merged.findings[0].recommendation


def test_invalid_suggested_fix_still_vulnerable_to_sqli():
    """A suggested fix that still uses an interpolated f-string in SQL query must be rejected."""
    f = _make_finding("SQL Injection", "critical", file="db.py", line=4)
    f.suggested_fix = 'query = f"SELECT * FROM users WHERE username = \'{user}\'"'

    llm_result = _base_llm_result(findings=[f])
    merged = validate_and_merge(llm_result, [])

    assert len(merged.findings) == 1
    assert merged.findings[0].suggested_fix is None


def test_unsupported_business_assumptions_sanitized():
    """Inventing arbitrary business tier discounts without specification must be sanitized."""
    f = _make_finding("Incorrect Discount for Premium Users", "medium", file="calc.py", line=14)
    f.description = "Premium discount should be 10% instead of 5%."
    f.suggested_fix = "return 10"

    llm_result = _base_llm_result(findings=[f])
    merged = validate_and_merge(llm_result, [])

    assert len(merged.findings) == 1
    finding = merged.findings[0]
    assert "Discrepancy" in finding.title
    assert "Avoid assuming arbitrary" in finding.description
    # Fix must not assert the invented arbitrary constant 10
    assert finding.suggested_fix is None


def test_summary_accuracy_no_false_unit_tests():
    """When no tests are present in the diff, summary must not falsely claim tests exist."""
    from app.tools.diff_parser import parse_git_diff

    diff = (
        "diff --git a/calc.py b/calc.py\n"
        "--- /dev/null\n"
        "+++ b/calc.py\n"
        "@@ -0,0 +1,5 @@\n"
        "+def add(a, b):\n"
        "+    return a + b\n"
    )
    diff_files = parse_git_diff(diff)

    llm_result = _base_llm_result(findings=[])
    llm_result.positive_observations = ["Great code style", "Comprehensive unit tests provided"]

    merged = validate_and_merge(llm_result, [], diff_files=diff_files)

    # Hallucinated test claim must be purged from positive observations
    assert "Comprehensive unit tests provided" not in merged.positive_observations
    # Summary must explicitly note absence of automated unit tests
    assert "No automated unit tests" in merged.summary


def test_finding_quality_id_and_evidence():
    """Every finding must carry a unique ID, evidence, and root cause."""
    from app.tools.diff_parser import parse_git_diff

    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- /dev/null\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+def run():\n"
        "+    eval(payload)\n"
    )
    diff_files = parse_git_diff(diff)

    f = _make_finding("Dangerous eval()", "critical", file="app.py", line=2)
    llm_result = _base_llm_result(findings=[f])
    merged = validate_and_merge(llm_result, [], diff_files=diff_files)

    finding = merged.findings[0]
    # Unique ID must be populated
    assert finding.id.startswith("CL-")
    # Code evidence must be extracted from line 2
    assert finding.evidence == "eval(payload)"
    # Root cause must be populated
    assert finding.root_cause is not None

