"""
Regression tests for Section 7: 29-Line Payment/Refund Code Review Scenario.

Verifies:
1. Rejection of false ZeroDivisionError on multiplication: return total_spend * 0.125
2. Detection of hardcoded live credential: sk_live_998877665544332211
3. Detection of dynamic receipt path traversal: /var/receipts/{transaction_id}.json
4. Detection of SSRF: requests.post(webhook_url, ...)
5. Detection of duplicate refund / race condition: webhook called before idempotency check
6. Clean behavior on safe, properly hardened payment processor
7. Strict fail-closed evidence validation on empty diffs and ambiguous basenames
"""
import pytest
from app.schemas.findings import Finding, ReviewResult
from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge, validate_source_evidence

TWENTY_NINE_LINE_CODE = """\
import os
import requests
import json

class PaymentProcessor:
    def __init__(self, api_key: str):
        self.api_key = api_key or "sk_live_998877665544332211"
        self.processed_transactions = set()

    def process_refund(self, transaction_id: str, amount: float, webhook_url: str):
        if amount == 0:
            return {"status": "skipped", "reason": "zero amount"}

        receipt_path = f"/var/receipts/{transaction_id}.json"
        with open(receipt_path, "r") as f:
            receipt = json.load(f)

        response = requests.post(webhook_url, json={"transaction_id": transaction_id, "refunded": amount})

        if transaction_id in self.processed_transactions:
            raise ValueError("Transaction already refunded")
        self.processed_transactions.add(transaction_id)

        return {"status": "success", "amount": amount}

    def calculate_vip_cashback(self, user_tier: str, total_spend: float):
        if user_tier == "gold":
            return total_spend * 0.125
        return 0.0
"""


def _make_29_line_diff() -> str:
    lines = TWENTY_NINE_LINE_CODE.splitlines()
    header = [
        "diff --git a/code.py b/code.py",
        "new file mode 100644",
        "--- /dev/null",
        "+++ b/code.py",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    diff_lines = [f"+{l}" for l in lines]
    return "\n".join(header + diff_lines) + "\n"


def test_29_line_detects_all_four_genuine_vulnerabilities():
    """Deterministic pattern detector must detect all 4 genuine vulnerabilities on the 29-line file."""
    diff = _make_29_line_diff()
    diff_files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, diff_files)

    titles = [f.title.lower() for f in findings]
    lines = [f.line for f in findings]

    # 1. Hardcoded credential on line 7
    assert any("credential" in t or "hardcoded" in t for t in titles)
    assert 7 in lines

    # 2. Path traversal on line 14
    assert any("path traversal" in t for t in titles)
    assert 14 in lines

    # 3. SSRF on line 18
    assert any("ssrf" in t or "request forgery" in t for t in titles)
    assert 18 in lines

    # 4. Race condition / Duplicate refund on line 20
    assert any("race condition" in t or "duplicate" in t for t in titles)
    assert any(line in (18, 20) for line in lines)

    # Must NOT invent ZeroDivisionError
    assert not any("zerodivision" in t for t in titles)


def test_29_line_rejects_hallucinated_zerodivision():
    """Validator must reject hallucinated ZeroDivisionError on return total_spend * 0.125."""
    diff = _make_29_line_diff()
    diff_files = parse_git_diff(diff)

    # Simulate the exact LLM finding shown in the user screenshot
    fake_zerodiv = Finding(
        title="ZeroDivisionError in calculate_vip_cashback",
        category="bug",
        severity="medium",
        file="code.py",
        line=27,
        root_cause="Division by zero when user_tier is 'gold'",
        evidence="return total_spend * 0.125",
        description="The function calculates the VIP cashback as 12.5% of the total spend. If user_tier is 'gold', this calculation will result in a division by zero if total_spend is zero.",
        impact="Process crash",
        recommendation="Add a check to handle the case where total_spend is zero.",
        suggested_fix="if total_spend == 0: return 0.0",
        confidence=0.80,
    )

    base_res = ReviewResult(
        summary="LLM review",
        overall_status="changes_requested",
        risk_level="medium",
        findings=[fake_zerodiv],
        positive_observations=[],
        missing_tests=[],
        deterministic_findings=[],
        llm_available=True,
    )

    det_findings = detect_risky_patterns(diff, diff_files)
    merged = validate_and_merge(base_res, det_findings, diff_files=diff_files)

    # Verify that the fake ZeroDivision finding was dropped
    assert not any("zerodivision" in f.title.lower() for f in merged.findings)
    assert merged.unverified_findings_count == 1

    # Verify that exactly 4 genuine findings remain
    assert len(merged.findings) == 4

    # Risk level must be escalated to high (contains critical/high security issues)
    assert merged.risk_level == "high"
    assert merged.overall_status == "changes_requested"


def test_safe_payment_processor_produces_no_false_positives():
    """A hardened, secure payment processor implementation must generate 0 false positives."""
    safe_code = """\
import os
import requests
import json

class PaymentProcessor:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("PAYMENT_API_KEY")
        self.processed_transactions = set()

    def process_refund(self, transaction_id: str, amount: float, webhook_url: str):
        if amount <= 0:
            return {"status": "skipped", "reason": "invalid amount"}

        # Idempotency check before external side effects
        if transaction_id in self.processed_transactions:
            raise ValueError("Transaction already refunded")
        self.processed_transactions.add(transaction_id)

        # Safe sanitized path
        safe_id = os.path.basename(transaction_id)
        receipt_path = os.path.join("/var/receipts", f"{safe_id}.json")
        with open(receipt_path, "r") as f:
            receipt = json.load(f)

        # Allowlisted static webhook destination
        response = requests.post("https://api.payments.internal/webhook", json={"transaction_id": safe_id, "refunded": amount})
        return {"status": "success", "amount": amount}

    def calculate_vip_cashback(self, user_tier: str, total_spend: float):
        if user_tier == "gold":
            return total_spend * 0.125
        return 0.0
"""
    lines = safe_code.splitlines()
    header = [
        "diff --git a/safe_payment.py b/safe_payment.py",
        "--- /dev/null",
        "+++ b/safe_payment.py",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    diff = "\n".join(header + [f"+{l}" for l in lines]) + "\n"
    diff_files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, diff_files)

    assert findings == []


def test_validate_source_evidence_fails_closed_when_diff_missing():
    """validate_source_evidence must fail closed when diff_files is empty or None."""
    finding = Finding(
        title="High Severity Security Issue",
        category="security",
        severity="high",
        file="code.py",
        line=10,
        evidence="some_code()",
        description="test",
    )
    valid, f_out, reason = validate_source_evidence(finding, diff_files=[], file_lines={}, file_all_code={})
    assert valid is False
    assert f_out is None
    assert "unavailable" in reason.lower()

    valid2, f_out2, reason2 = validate_source_evidence(finding, diff_files=None, file_lines={}, file_all_code={})
    assert valid2 is False
    assert f_out2 is None


def test_validate_source_evidence_rejects_ambiguous_basename():
    """Validator must reject findings when multiple files share the basename and path is ambiguous."""
    finding = Finding(
        title="Issue in service",
        category="bug",
        severity="medium",
        file="service.py",  # ambiguous: both auth/service.py and billing/service.py exist
        line=5,
        evidence="return True",
        description="test",
    )
    diff = (
        "diff --git a/auth/service.py b/auth/service.py\n"
        "--- /dev/null\n"
        "+++ b/auth/service.py\n"
        "@@ -0,0 +1,5 @@\n"
        "+def login():\n"
        "+    return True\n"
        "diff --git a/billing/service.py b/billing/service.py\n"
        "--- /dev/null\n"
        "+++ b/billing/service.py\n"
        "@@ -0,0 +1,5 @@\n"
        "+def invoice():\n"
        "+    return True\n"
    )
    diff_files = parse_git_diff(diff)
    file_lines = {
        df.new_path: {i: l.content for i, l in enumerate(df.hunks[0].lines, 1)}
        for df in diff_files
    }
    file_all_code = {
        df.new_path: "\n".join(l.content for l in df.hunks[0].lines)
        for df in diff_files
    }

    valid, f_out, reason = validate_source_evidence(finding, diff_files, file_lines, file_all_code)
    assert valid is False
    assert f_out is None
    assert "ambiguous" in reason.lower()
