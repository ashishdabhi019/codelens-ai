"""
Regression tests for false-positive reduction, SQL injection detection,
evidence validation, security detections, and the 140-line payment test.
"""
import pytest
from app.schemas.findings import Finding, ReviewResult
from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge, validate_source_evidence
from app.tools.fix_validator import validate_suggested_fix


def _make_review_result(findings=None, llm_available=True, partial=False) -> ReviewResult:
    return ReviewResult(
        summary="Test summary",
        overall_status="approved",
        risk_level="low",
        files_reviewed=1,
        findings=findings or [],
        llm_available=llm_available,
        partial_analysis=partial,
    )


# ============================================================================
# 1. SQL INJECTION REGRESSION TESTS (POSITIVE & NEGATIVE)
# ============================================================================

def test_detect_vulnerable_fstring_sql_assignment():
    """Detects SQL injection where f-string query is assigned to a variable and executed."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,6 @@
+def get_user(cursor, user_id):
+    query = f"SELECT id, name FROM users WHERE id = {user_id}"
+    cursor.execute(query)
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    sqli_findings = [f for f in findings if "SQL" in f.title]
    assert len(sqli_findings) >= 1
    assert any(f.line in (2, 3) for f in sqli_findings)


def test_detect_vulnerable_concat_sql():
    """Detects SQL injection via string concatenation."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,5 @@
+def find_user(cursor, username):
+    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)


def test_detect_vulnerable_format_sql():
    """Detects SQL injection via .format() call."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,5 @@
+def find_user(cursor, username):
+    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(username))
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)


def test_safe_parameterized_select_not_flagged():
    """Safe parameterized SELECT with placeholders must not be flagged as SQL injection."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,5 @@
+def get_user(cursor, user_id):
+    cursor.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_safe_parameterized_update_multiline_not_flagged():
    """Multi-line parameterized UPDATE must not be flagged as SQL injection."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,8 @@
+def reset_password(cursor, hashed_password, user_id):
+    cursor.execute(
+        "UPDATE users SET password = ? WHERE id = ?",
+        (hashed_password, user_id)
+    )
+    return True
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_non_sql_execute_method_not_flagged():
    """Non-database execute() calls (e.g. task.execute(), command.execute()) must not be flagged."""
    diff = """\
diff --git a/worker.py b/worker.py
--- /dev/null
+++ b/worker.py
@@ -0,0 +1,4 @@
+def run_task(task, context):
+    task.execute(context)
+    return {"done": True}
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_ordinary_arithmetic_not_flagged_as_sql():
    """Ordinary arithmetic functions contain no SQL and must not produce SQL findings."""
    diff = """\
diff --git a/math_ops.py b/math_ops.py
--- /dev/null
+++ b/math_ops.py
@@ -0,0 +1,4 @@
+def calculate_discount(price, discount):
+    final_price = price * (1 - discount / 100)
+    return final_price
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_dynamic_sql_assigned_never_executed_not_flagged():
    """Dynamic SQL query assigned to variable but never executed in a sink must not be flagged."""
    diff = """\
diff --git a/report.py b/report.py
--- /dev/null
+++ b/report.py
@@ -0,0 +1,4 @@
+def prepare_report(user_input):
+    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
+    return "Report prepared"
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_dynamic_sql_reassigned_to_safe_query_not_flagged():
    """Dynamic SQL variable reassigned to a safe query before execution must not be flagged."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,6 @@
+def get_user(cursor, user_id):
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    query = "SELECT * FROM users WHERE id = ?"
+    cursor.execute(query, (user_id,))
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SQL" in f.title for f in findings)


def test_safe_query_reassigned_to_dynamic_query_flagged():
    """Safe query variable reassigned to dynamic SQL before execution must be detected."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,6 @@
+def get_user(cursor, user_id):
+    query = "SELECT * FROM users WHERE id = ?"
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    cursor.execute(query)
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)


def test_two_functions_independent_sql_scopes():
    """Two independent functions using the same variable name must not pollute each other's scopes."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,9 @@
+def prepare_report(user_input):
+    query = f"SELECT * FROM users WHERE name = {user_input}"
+    return "Report"
+
+def safe_lookup(cursor, user_id):
+    query = "SELECT * FROM users WHERE id = ?"
+    cursor.execute(query, (user_id,))
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    # Neither should be flagged: prepare_report has no execution sink, safe_lookup is parameterized
    assert not any("SQL" in f.title for f in findings)


def test_sql_variable_alias_executed_flagged():
    """Tracking aliases (q2 = q1) must flag when alias reaches database execution sink."""
    diff = """\
diff --git a/repo.py b/repo.py
--- /dev/null
+++ b/repo.py
@@ -0,0 +1,6 @@
+def find_user(cursor, user_id):
+    q1 = f"SELECT * FROM users WHERE id = {user_id}"
+    q2 = q1
+    cursor.execute(q2)
+    return cursor.fetchone()
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)


def test_discount_amount_not_flagged_as_broken():
    """discount_amount = price * (discount / 100) calculates the discount amount and must not be flagged."""
    diff = """\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,4 @@
+def calculate_discount_amount(price, discount):
+    discount_amount = price * (discount / 100)
+    return discount_amount
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("discount" in f.title.lower() for f in findings)


def test_final_price_incorrect_formula_flagged():
    """final_price = price * (discount / 100) claiming to be final payable price must be detected."""
    diff = """\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,4 @@
+def calculate_broken_price(price, discount):
+    final_price = price * (discount / 100)
+    return final_price
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("discount" in f.title.lower() for f in findings)


def test_valid_bank_transfer_not_flagged():
    """Bank transfer that checks receiver, checks balance, and updates atomically must not be flagged."""
    diff = """\
diff --git a/bank.py b/bank.py
--- /dev/null
+++ b/bank.py
@@ -0,0 +1,11 @@
+def transfer_money(cursor, sender_id, receiver_id, amount):
+    receiver = cursor.execute("SELECT id FROM accounts WHERE id = ?", (receiver_id,)).fetchone()
+    if not receiver:
+        return {"error": "Receiver not found"}
+    sender = cursor.execute("SELECT balance FROM accounts WHERE id = ?", (sender_id,)).fetchone()
+    if not sender or sender[0] < amount:
+        return {"error": "Insufficient funds"}
+    cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, sender_id))
+    cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
+    return {"status": "success"}
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("transfer" in f.title.lower() for f in findings)


# ============================================================================
# 2. EVIDENCE VALIDATION & THEFT REJECTION
# ============================================================================

def test_reject_sqli_with_evidence_copied_from_another_function():
    """Validator must reject SQL injection findings on non-SQL functions that reuse evidence from line 17."""
    diff = """\
diff --git a/code.py b/code.py
--- /dev/null
+++ b/code.py
@@ -0,0 +1,25 @@
+def get_user(cursor, user_id):
+    query = f"SELECT id, name FROM users WHERE id = {user_id}"
+    cursor.execute(query)
+    return cursor.fetchone()
+
+def calculate_average(numbers):
+    total = sum(numbers)
+    return total / len(numbers)
+"""
    files = parse_git_diff(diff)
    f_real = Finding(
        title="SQL Injection in get_user",
        category="security",
        severity="critical",
        file="code.py",
        line=2,
        evidence='query = f"SELECT id, name FROM users WHERE id = {user_id}"',
        description="Dynamic SQL query in get_user",
        impact="Data leak",
        recommendation="Use parameterized query",
    )
    f_fake = Finding(
        title="SQL Injection in calculate_average",
        category="security",
        severity="medium",
        file="code.py",
        line=7,
        evidence='query = f"SELECT id, name FROM users WHERE id = {user_id}"',
        description="SQL injection in calculate_average",
        impact="Data leak",
        recommendation="Use parameterized query",
    )
    result = validate_and_merge(_make_review_result([f_real, f_fake]), [], diff_files=files)
    # The real finding at line 2 must be kept, but the hallucinated finding at line 7 must be rejected
    assert len(result.findings) == 1
    assert result.findings[0].line == 2
    assert result.unverified_findings_count == 1


def test_reject_sqli_on_pure_non_sql_function():
    """Validator rejects SQL injection claim on functions with no SQL operations even if evidence is crafted."""
    diff = """\
diff --git a/code.py b/code.py
--- /dev/null
+++ b/code.py
@@ -0,0 +1,5 @@
+def evaluate_expression(expression):
+    return eval(expression)
+"""
    files = parse_git_diff(diff)
    f = Finding(
        title="SQL Injection in evaluate_expression",
        category="security",
        severity="medium",
        file="code.py",
        line=2,
        evidence="return eval(expression)",
        description="eval causes SQL injection",
        impact="Exploitation",
        recommendation="Avoid eval",
    )
    result = validate_and_merge(_make_review_result([f]), [], diff_files=files)
    assert len(result.findings) == 0
    assert result.unverified_findings_count == 1


# ============================================================================
# 3. SECURITY DETECTIONS (SECRETS, EVAL, PICKLE, HASHING, SSRF, PATH TRAVERSAL)
# ============================================================================

def test_hardcoded_credential_detected():
    """Detects live secret key string assignment."""
    diff = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+API_SECRET = "sk_live_123456789abcdef"
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("credential" in f.title.lower() for f in findings)


def test_env_var_secret_not_flagged():
    """Reading secret from os.getenv is safe and must not produce credential findings."""
    diff = """\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+API_SECRET = os.getenv("PAYMENT_API_SECRET")
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("credential" in f.title.lower() for f in findings)


def test_unsafe_pickle_detected():
    """Detects unsafe pickle.loads() on variable input."""
    diff = """\
diff --git a/loader.py b/loader.py
--- /dev/null
+++ b/loader.py
@@ -0,0 +1,3 @@
+import pickle
+def load_user(data):
+    return pickle.loads(data)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("pickle" in f.title.lower() for f in findings)


def test_safe_json_parsing_not_flagged():
    """json.loads is safe and must not be flagged as deserialization vulnerability."""
    diff = """\
diff --git a/loader.py b/loader.py
--- /dev/null
+++ b/loader.py
@@ -0,0 +1,3 @@
+import json
+def load_user(data):
+    return json.loads(data)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("pickle" in f.title.lower() for f in findings)


def test_dynamic_eval_detected():
    """Detects dangerous eval() on variable input."""
    diff = """\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,2 @@
+def compute(expr):
+    return eval(expr)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("eval" in f.title.lower() for f in findings)


def test_password_hashing_recommends_bcrypt_or_argon2():
    """Weak MD5 password hashing must be flagged and recommend bcrypt/Argon2id (NOT SHA-256)."""
    diff = """\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,4 @@
+import hashlib
+def hash_password(new_password):
+    hashed_password = hashlib.md5(new_password.encode()).hexdigest()
+    return hashed_password
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    pwd_findings = [f for f in findings if "password" in f.title.lower() or "md5" in f.title.lower()]
    assert len(pwd_findings) >= 1
    f = pwd_findings[0]
    assert "argon2" in f.recommendation.lower() or "bcrypt" in f.recommendation.lower()
    assert "sha256" not in f.recommendation.lower() or "instead of" in f.recommendation.lower()


def test_ssrf_detected_on_dynamic_url():
    """Detects SSRF when requests.post is dispatched to dynamic webhook_url."""
    diff = """\
diff --git a/notify.py b/notify.py
--- /dev/null
+++ b/notify.py
@@ -0,0 +1,4 @@
+import requests
+def send_webhook(webhook_url, payload):
+    return requests.post(webhook_url, json=payload, timeout=5)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SSRF" in f.title for f in findings)


def test_safe_fixed_webhook_url_not_flagged_as_ssrf():
    """Fixed literal URLs are trusted destinations and must not be flagged as SSRF."""
    diff = """\
diff --git a/notify.py b/notify.py
--- /dev/null
+++ b/notify.py
@@ -0,0 +1,4 @@
+import requests
+def send_notification(payload):
+    return requests.post("https://api.mycompany.com/webhook", json=payload, timeout=5)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert not any("SSRF" in f.title for f in findings)


def test_path_traversal_via_dynamic_file_path():
    """Detects user-controlled file path formatting reaching open()."""
    diff = """\
diff --git a/upload.py b/upload.py
--- /dev/null
+++ b/upload.py
@@ -0,0 +1,5 @@
+def save_avatar(user_id, content):
+    file_path = f"/var/www/uploads/{user_id}.jpg"
+    with open(file_path, "wb") as f:
+        f.write(content)
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("Path Traversal" in f.title for f in findings)


# ============================================================================
# 4. LOGIC BUG DETECTIONS (DISCOUNT & TRANSFER MONEY)
# ============================================================================

def test_detect_incorrect_discount_calculation():
    """Detects final_price = price * (discount / 100) calculating discount deduction amount."""
    diff = """\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,4 @@
+def calculate_discount(price, discount):
+    final_price = price * (discount / 100)
+    return final_price
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    disc_findings = [f for f in findings if "discount" in f.title.lower()]
    assert len(disc_findings) >= 1
    assert "price * (1 - discount" in disc_findings[0].suggested_fix


def test_detect_transfer_money_unconditional_success():
    """Detects unconditional return {'status': 'success'} when balance check can fail."""
    diff = """\
diff --git a/bank.py b/bank.py
--- /dev/null
+++ b/bank.py
@@ -0,0 +1,11 @@
+def transfer_money(cursor, sender_id, receiver_id, amount):
+    sender = cursor.execute("SELECT balance FROM accounts WHERE id = ?", (sender_id,)).fetchone()
+    if not sender:
+        return {"error": "Not found"}
+    if sender[0] >= amount:
+        cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, sender_id))
+        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
+    return {"status": "success"}
+"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    transfer_findings = [f for f in findings if "transfer" in f.title.lower()]
    assert len(transfer_findings) >= 1


# ============================================================================
# 5. FIX VALIDATION REGRESSION TESTS
# ============================================================================

def test_fix_validation_valid_python_syntax():
    """Valid Python fix is validated and given 'validated_syntax' status."""
    f = Finding(
        title="ZeroDivision on empty list",
        category="bug",
        severity="high",
        file="calc.py",
        line=2,
        description="Crash on empty input",
        impact="Crash",
        recommendation="Guard input",
        suggested_fix="if not numbers:\n    return 0.0\nreturn sum(numbers) / len(numbers)",
    )
    val = validate_suggested_fix(f, file_path="calc.py")
    assert val.sanitized_fix is not None
    assert val.fix_status == "validated_syntax"


def test_fix_validation_rejects_invalid_syntax():
    """Suggested fix with syntax errors is rejected."""
    f = Finding(
        title="Bad syntax fix",
        category="bug",
        severity="medium",
        file="app.py",
        suggested_fix="def broken_syntax(:\n    return",
    )
    val = validate_suggested_fix(f, file_path="app.py")
    assert val.sanitized_fix is None
    assert val.fix_status == "rejected"


def test_fix_validation_rejects_undefined_variable():
    """Fix introducing undefined variables when original code is available is rejected."""
    f = Finding(
        title="Fix with undefined var",
        category="bug",
        severity="medium",
        file="math_ops.py",
        suggested_fix="return unknown_undefined_variable_123 * 2",
    )
    val = validate_suggested_fix(f, original_code="def double(x):\n    return x * 2", file_path="math_ops.py")
    assert val.sanitized_fix is None
    assert val.fix_status == "rejected"
    assert "undefined variable" in val.rejection_reason.lower()


def test_fix_validation_rejects_reintroduced_sqli():
    """Fix that re-introduces an f-string SQL query is rejected."""
    f = Finding(
        title="SQL Injection in user search",
        category="security",
        severity="critical",
        file="db.py",
        suggested_fix='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )
    val = validate_suggested_fix(f, file_path="db.py")
    assert val.sanitized_fix is None
    assert val.fix_status == "rejected"


def test_fix_validation_non_python_marked_proposed():
    """Fix for non-Python languages is marked 'proposed', never 'passed_tests' without running tests."""
    f = Finding(
        title="JavaScript DOM XSS",
        category="security",
        severity="critical",
        file="component.tsx",
        suggested_fix="element.textContent = sanitizedInput;",
    )
    val = validate_suggested_fix(f, file_path="component.tsx")
    assert val.fix_status == "proposed"
    assert val.fix_status != "passed_tests"


# ============================================================================
# 6. END-TO-END 140-LINE PAYMENT DIFF VERIFICATION
# ============================================================================

def test_140_payment_diff_zero_sql_false_positives():
    """
    Complete end-to-end regression test for the 140-line payment file.
    Must produce ZERO false positive SQL injection findings across:
    transfer_money, calculate_discount, calculate_average, load_user_data,
    evaluate_expression, download_profile_image, reset_password, get_api_secret,
    safe_user_lookup, and process_refund.
    Must accurately detect genuine issues (SQLi in get_user, hardcoded secret, etc.).
    """
    import os
    candidates = [
        "test_140_payment.diff",
        os.path.join(os.path.dirname(__file__), "..", "..", "test_140_payment.diff"),
        os.path.join(os.path.dirname(__file__), "test_140_payment.diff"),
    ]
    diff_path = next((c for c in candidates if os.path.exists(c)), "test_140_payment.diff")
    with open(diff_path) as f:
        diff_content = f.read()

    files = parse_git_diff(diff_content)
    deterministic = detect_risky_patterns(diff_content, files)

    # Simulate an LLM output that attempts to emit SQLi on all 10 non-SQL/parameterized functions
    hallucinated_llm_findings = [
        Finding(
            title=f"SQL Injection in {fn_name}",
            category="security",
            severity="medium",
            file="code.py",
            line=line,
            evidence='query = f"SELECT id, name, balance FROM users WHERE id = {user_id}"',
            description=f"SQL injection defect in {fn_name}",
            impact="Data breach",
            recommendation="Use parameterized queries",
        )
        for fn_name, line in [
            ("transfer_money", 28),
            ("calculate_discount", 57),
            ("calculate_average", 64),
            ("load_user_data", 69),
            ("evaluate_expression", 73),
            ("download_profile_image", 77),
            ("reset_password", 93),
            ("get_api_secret", 112),
            ("safe_user_lookup", 121),
            ("process_refund", 131),
        ]
    ]

    llm_result = _make_review_result(hallucinated_llm_findings, llm_available=True)
    merged = validate_and_merge(llm_result, deterministic, diff_files=files)

    # Check SQL findings
    sql_findings = [f for f in merged.findings if "sql" in f.title.lower()]
    # ONLY the genuine SQL injection in get_user (line 17 or 18) must be retained
    assert len(sql_findings) == 1
    assert sql_findings[0].line in (17, 18)
    assert "sql" in sql_findings[0].title.lower()

    # Verify no false positive SQL findings exist on the other 10 functions
    for bad_fn in [
        "transfer_money", "calculate_discount", "calculate_average", "load_user_data",
        "evaluate_expression", "download_profile_image", "reset_password",
        "get_api_secret", "safe_user_lookup", "process_refund"
    ]:
        assert not any(f"in `{bad_fn}`" in f.title or f"in {bad_fn}" in f.title for f in sql_findings)

    # Verify genuine detections were retained
    titles = [f.title for f in merged.findings]
    assert any("eval" in t.lower() for t in titles)
    assert any("credential" in t.lower() for t in titles)
    assert any("pickle" in t.lower() for t in titles)
    assert any("zerodivision" in t.lower() for t in titles)
    assert any("ssrf" in t.lower() for t in titles)
    assert any("password" in t.lower() for t in titles)
    assert any("discount" in t.lower() for t in titles)
    assert any("path traversal" in t.lower() for t in titles)
    assert any("transfer_money" in t.lower() for t in titles)
