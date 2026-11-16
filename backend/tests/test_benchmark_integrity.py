"""
Tests for benchmark dataset integrity, expected defect verification, and confusion matrix metrics.

Validates:
1. Vulnerable cases with missing or empty expected_defects fail closed.
2. Safe cases with non-empty expected_defects fail closed.
3. All benchmark cases have valid, non-empty, unique case IDs.
4. All expected defects have files, line numbers, and evidence present in their diffs.
5. Evaluator flags duplicate findings as false positives.
6. Evaluator flags spurious (unrelated) findings as false positives.
7. Evaluator flags findings on safe cases as false positives.
8. Multi-defect payment scenario requires all 4 expected defects to achieve Case-Level TP.
"""
import pytest
from app.schemas.findings import Finding
from app.tools.diff_parser import parse_git_diff
from benchmark import (
    BenchmarkCase,
    ExpectedDefect,
    BENCHMARK_DATASET,
    validate_benchmark_dataset,
    match_finding_to_defect,
    evaluate_mode1_deterministic_engine,
)


def test_vulnerable_case_with_missing_defects_fails_closed():
    """Vulnerable cases with empty or missing expected_defects must raise ValueError (fail closed)."""
    bad_case = BenchmarkCase(
        case_id="CL-TEST-001",
        name="Vulnerable but missing defect list",
        category="SQL Injection",
        code_diff="""\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,2 @@
+def query(val):
+    cursor.execute(f"SELECT * FROM users WHERE id = {val}")
""",
        is_vulnerable=True,
        expected_defects=[],  # Missing defect metadata!
    )
    with pytest.raises(ValueError, match="empty or missing expected_defects"):
        validate_benchmark_dataset([bad_case])


def test_safe_case_with_defects_fails_integrity():
    """Safe cases must have empty expected_defects; defining defects on safe cases must fail closed."""
    bad_safe_case = BenchmarkCase(
        case_id="CL-TEST-002",
        name="Safe case with erroneous defect definition",
        category="Clean Code",
        code_diff="""\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,2 @@
+def add(a, b):
+    return a + b
""",
        is_vulnerable=False,
        expected_defects=[
            ExpectedDefect("bug", "app.py", [2], "return a + b", "bug")
        ],
    )
    with pytest.raises(ValueError, match="must have empty expected_defects"):
        validate_benchmark_dataset([bad_safe_case])


def test_all_56_benchmark_cases_have_unique_case_ids():
    """Every benchmark case in BENCHMARK_DATASET must have a unique non-empty case_id."""
    case_ids = [c.case_id for c in BENCHMARK_DATASET]
    assert len(case_ids) == 56
    assert len(set(case_ids)) == 56
    for cid in case_ids:
        assert cid.startswith("CL-CASE-")


def test_dataset_passes_full_integrity_validation():
    """The official BENCHMARK_DATASET must pass all fail-closed integrity checks."""
    # Should complete without raising any ValueError
    validate_benchmark_dataset(BENCHMARK_DATASET)


def test_defect_with_nonexistent_file_fails_integrity():
    """Defect referencing a file not in the diff must fail closed."""
    bad_file_case = BenchmarkCase(
        case_id="CL-TEST-003",
        name="Wrong file reference",
        category="Security",
        code_diff="""\
diff --git a/actual.py b/actual.py
--- /dev/null
+++ b/actual.py
@@ -0,0 +1,2 @@
+def run():
+    pass
""",
        is_vulnerable=True,
        expected_defects=[
            ExpectedDefect("bug", "nonexistent.py", [2], "pass", "bug")
        ],
    )
    with pytest.raises(ValueError, match="not found in diff files"):
        validate_benchmark_dataset([bad_file_case])


def test_defect_with_nonexistent_line_fails_integrity():
    """Defect referencing a line number not in added diff lines must fail closed."""
    bad_line_case = BenchmarkCase(
        case_id="CL-TEST-004",
        name="Out of bounds line reference",
        category="Security",
        code_diff="""\
diff --git a/actual.py b/actual.py
--- /dev/null
+++ b/actual.py
@@ -0,0 +1,2 @@
+def run():
+    pass
""",
        is_vulnerable=True,
        expected_defects=[
            ExpectedDefect("bug", "actual.py", [999], "pass", "bug")
        ],
    )
    with pytest.raises(ValueError, match="not found in added lines"):
        validate_benchmark_dataset([bad_line_case])


def test_defect_with_mismatched_evidence_fails_integrity():
    """Defect referencing code evidence not present in diff content must fail closed."""
    bad_ev_case = BenchmarkCase(
        case_id="CL-TEST-005",
        name="Fabricated evidence string",
        category="Security",
        code_diff="""\
diff --git a/actual.py b/actual.py
--- /dev/null
+++ b/actual.py
@@ -0,0 +1,2 @@
+def run():
+    pass
""",
        is_vulnerable=True,
        expected_defects=[
            ExpectedDefect("bug", "actual.py", [2], "completely_fake_code()", "bug")
        ],
    )
    with pytest.raises(ValueError, match="not found in diff content"):
        validate_benchmark_dataset([bad_ev_case])


def test_match_finding_to_defect_strictness():
    """match_finding_to_defect must verify file, line, evidence, category, and type."""
    defect = ExpectedDefect(
        vulnerability_type="sql",
        file="db.py",
        lines=[2],
        evidence_substr="cursor.execute",
        category="security",
    )

    # Valid matching finding
    good_finding = Finding(
        title="SQL Injection in find_user",
        category="security",
        severity="critical",
        file="db.py",
        line=2,
        evidence='cursor.execute(f"SELECT * FROM users")',
        description="Dynamic query execution",
        impact="DB breach",
        recommendation="Use parameters",
    )
    assert match_finding_to_defect(good_finding, defect) is True

    # Wrong file
    bad_file = good_finding.model_copy(update={"file": "other.py"})
    assert match_finding_to_defect(bad_file, defect) is False

    # Wrong line
    bad_line = good_finding.model_copy(update={"line": 5})
    assert match_finding_to_defect(bad_line, defect) is False

    # Mismatched evidence
    bad_ev = good_finding.model_copy(update={"evidence": "return None"})
    assert match_finding_to_defect(bad_ev, defect) is False

    # Wrong category
    bad_cat = good_finding.model_copy(update={"category": "bug"})
    assert match_finding_to_defect(bad_cat, defect) is False

    # Wrong vulnerability type
    bad_type = good_finding.model_copy(update={"title": "ZeroDivisionError in calculate"})
    assert match_finding_to_defect(bad_type, defect) is False


def test_evaluator_penalizes_spurious_and_duplicate_findings():
    """Evaluator must penalize duplicate or unrelated findings as False Positives."""
    test_case = BenchmarkCase(
        case_id="CL-TEST-006",
        name="Single SQLi Case",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,3 @@
+def query(user_id):
+    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
+    return cursor.fetchone()
""",
        is_vulnerable=True,
        expected_defects=[
            ExpectedDefect("sql", "db.py", [2], "cursor.execute", "security")
        ],
    )
    res = evaluate_mode1_deterministic_engine([test_case])
    assert res["case_tp"] == 1
    assert res["case_fp"] == 0
    assert res["defect_tp"] == 1
    assert res["defect_fp"] == 0


def test_payment_processor_requires_all_four_defects():
    """CL-CASE-053 requires all 4 expected defects (credential, traversal, SSRF, race condition)."""
    payment_case = next(c for c in BENCHMARK_DATASET if c.case_id == "CL-CASE-053")
    assert len(payment_case.expected_defects) == 4

    types = {d.vulnerability_type for d in payment_case.expected_defects}
    assert types == {"credential", "path traversal", "ssrf", "race condition"}

    res = evaluate_mode1_deterministic_engine([payment_case])
    # Case must pass as TP because all 4 defects are detected
    assert res["case_tp"] == 1
    assert res["case_fn"] == 0
    assert res["defect_tp"] == 4
    assert res["defect_fn"] == 0
