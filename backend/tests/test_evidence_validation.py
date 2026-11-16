"""Tests for strict finding validation, source evidence verification, and false-positive reduction."""
import pytest
from app.schemas.findings import Finding, ReviewResult
from app.tools.diff_parser import parse_git_diff
from app.tools.review_validator import validate_and_merge, validate_source_evidence


def _make_review_result(findings=None) -> ReviewResult:
    return ReviewResult(
        summary="Test summary",
        overall_status="approved",
        risk_level="low",
        files_reviewed=1,
        findings=findings or [],
        llm_available=True,
    )


def test_reject_nonexistent_file():
    """Findings referencing a file that does not exist in the diff must be rejected."""
    diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def main():
+    return True
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Hallucinated Bug",
        category="bug",
        severity="high",
        file="completely_different_file.py",
        line=10,
        evidence="some code",
        description="Bug in nonexistent file",
        impact="None",
        recommendation="Fix it",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0
    assert result.unverified_findings_count == 1


def test_reject_nonexistent_line_number():
    """Findings with line numbers outside the diff file range and mismatched evidence must be rejected."""
    diff = """\
diff --git a/app.py b/app.py
--- /dev/null
+++ b/app.py
@@ -0,0 +1,3 @@
+def add(a, b):
+    return a + b
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Out of Bounds Line",
        category="bug",
        severity="medium",
        file="app.py",
        line=999,
        evidence="def imaginary(): pass",
        description="Bug on nonexistent line",
        impact="None",
        recommendation="Fix it",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0
    assert result.unverified_findings_count == 1


def test_reject_zerodivision_on_multiplication():
    """ZeroDivision claims on multiplication expressions (like total_spend * 0.125) must be rejected."""
    diff = """\
diff --git a/code.py b/code.py
--- /dev/null
+++ b/code.py
@@ -0,0 +1,5 @@
+def calculate_vip_cashback(user_tier: str, total_spend: float):
+    if user_tier == "gold":
+        return total_spend * 0.125
+    return 0.0
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="ZeroDivisionError in calculate_vip_cashback",
        category="bug",
        severity="medium",
        file="code.py",
        line=3,
        evidence="return total_spend * 0.125",
        description="The calculation will result in a division by zero if total_spend is zero.",
        impact="Crashes with ZeroDivisionError",
        recommendation="Add a check if total_spend == 0",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    # Finding must be rejected because line 3 is multiplication, not division
    assert len(result.findings) == 0
    assert result.unverified_findings_count == 1


def test_reject_zerodivision_on_nonzero_literal_denominator():
    """Division by a non-zero constant (e.g. / 100) cannot cause ZeroDivisionError."""
    diff = """\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,3 @@
+def to_percent(val):
+    return val / 100.0
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Potential ZeroDivisionError in to_percent",
        category="bug",
        severity="high",
        file="calc.py",
        line=2,
        evidence="return val / 100.0",
        description="Division by zero may occur.",
        impact="Process crash",
        recommendation="Guard divisor",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0


def test_reject_sqli_on_safe_parameterized_query():
    """A parameterized SQL query (e.g. cursor.execute('SELECT ... WHERE id = ?', (uid,))) is safe."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,3 @@
+def get_user(cursor, uid):
+    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))
+    return cursor.fetchone()
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="SQL Injection in get_user",
        category="security",
        severity="critical",
        file="repo.py",
        line=2,
        evidence='cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))',
        description="Query contains SQL injection vulnerability",
        impact="Data leak",
        recommendation="Use parameterization",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    # Must reject false positive
    assert len(result.findings) == 0


def test_reject_eval_on_literal_eval():
    """ast.literal_eval is safe and must not be flagged as arbitrary code execution."""
    diff = """\
diff --git a/parser.py b/parser.py
--- /dev/null
+++ b/parser.py
@@ -0,0 +1,4 @@
+import ast
+def parse_data(raw):
+    return ast.literal_eval(raw)
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Dangerous eval() vulnerability",
        category="security",
        severity="critical",
        file="parser.py",
        line=3,
        evidence="return ast.literal_eval(raw)",
        description="eval allows arbitrary code execution",
        impact="RCE",
        recommendation="Avoid eval",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0


def test_reject_hardcoded_secret_on_env_var():
    """Reading configuration from os.getenv is safe and must not be flagged as hardcoded credential."""
    diff = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+API_KEY = os.getenv("STRIPE_SECRET_KEY")
+"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Hardcoded credential detected",
        category="security",
        severity="high",
        file="config.py",
        line=2,
        evidence='API_KEY = os.getenv("STRIPE_SECRET_KEY")',
        description="API key is hardcoded in file",
        impact="Secret exposure",
        recommendation="Use env vars",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0


def test_accept_valid_finding_with_matching_evidence():
    """Valid findings matching real source lines and real defects are accepted."""
    diff = """\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,3 @@
+def login():
+    token = "sk_live_1234567890abcdef1234"
+    return token
"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Hardcoded credential detected",
        category="security",
        severity="high",
        file="auth.py",
        line=2,
        evidence='token = "sk_live_1234567890abcdef1234"',
        description="Live secret token hardcoded in source.",
        impact="Secret exposure",
        recommendation="Use environment variables.",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 1
    assert result.findings[0].file == "auth.py"
    assert result.findings[0].line == 2


def test_reject_ambiguous_basename_matches():
    """When multiple files share the same basename, an unqualified finding file must be rejected as ambiguous."""
    diff = """\
diff --git a/pkg_a/handler.py b/pkg_a/handler.py
--- /dev/null
+++ b/pkg_a/handler.py
@@ -0,0 +1,3 @@
+def handle():
+    pass
diff --git a/pkg_b/handler.py b/pkg_b/handler.py
--- /dev/null
+++ b/pkg_b/handler.py
@@ -0,0 +1,3 @@
+def handle():
+    pass
+"""
    diff_files = parse_git_diff(diff)
    f = Finding(
        title="Issue in handler",
        category="bug",
        severity="medium",
        file="handler.py",  # Ambiguous! Both pkg_a/handler.py and pkg_b/handler.py exist
        line=1,
        evidence="def handle():",
        description="Ambiguous file test",
        impact="None",
        recommendation="Fix",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=diff_files)
    assert len(result.findings) == 0
    assert result.unverified_findings_count == 1


def test_reject_evidence_copied_from_unrelated_function():
    """Evidence copied across unrelated functions (>3 lines away) must be rejected."""
    diff = """\
diff --git a/service.py b/service.py
--- /dev/null
+++ b/service.py
@@ -0,0 +1,15 @@
+def func_one():
+    sensitive_token_variable = "abc123secretvalue"
+    return True
+
+def func_two():
+    pass
+
+def func_three():
+    return False
+"""
    diff_files = parse_git_diff(diff)
    # First finding on line 2 with sensitive token
    f1 = Finding(
        title="Hardcoded credential in func_one",
        category="security",
        severity="high",
        file="service.py",
        line=2,
        evidence='sensitive_token_variable = "abc123secretvalue"',
        description="First finding",
        impact="Leak",
        recommendation="Env var",
    )
    # Second finding claims line 11 (func_three) but copies the exact evidence from line 2!
    f2 = Finding(
        title="Stolen evidence in func_three",
        category="security",
        severity="high",
        file="service.py",
        line=11,
        evidence='sensitive_token_variable = "abc123secretvalue"',  # Copied from line 2!
        description="Second finding with stolen evidence",
        impact="Leak",
        recommendation="Env var",
    )
    result = validate_and_merge(_make_review_result([f1, f2]), [], diff_files=diff_files)
    # f1 should be accepted, but f2 must be rejected!
    assert len(result.findings) == 1
    assert result.findings[0].line == 2
    assert result.unverified_findings_count == 1

