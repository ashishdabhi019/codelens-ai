"""Tests for validate_suggested_fix."""
import pytest
from app.schemas.findings import Finding
from app.tools.fix_validator import validate_suggested_fix


def _make_finding(title: str, fix: str = None) -> Finding:
    return Finding(
        title=title,
        category="bug",
        severity="high",
        file="foo.py",
        line=1,
        description="Issue description",
        impact="Impact description",
        recommendation="Fix recommendation",
        suggested_fix=fix,
    )


def test_valid_fix():
    f = _make_finding("Discount Bug", "final_price = price * (1 - discount / 100)")
    fix, reason = validate_suggested_fix(f, "final_price = price / (1 - discount / 100)")
    assert fix == "final_price = price * (1 - discount / 100)"
    assert reason is None


def test_reject_fix_identical_to_original_code():
    orig = "final_price = price / (1 - discount / 100)"
    f = _make_finding("Discount Bug", orig)
    fix, reason = validate_suggested_fix(f, orig)
    assert fix is None
    assert "identical" in reason.lower()


def test_reject_placeholder_comment():
    f = _make_finding("Any Bug", "# TODO: implement safe query")
    fix, reason = validate_suggested_fix(f, "orig = 1")
    assert fix is None
    assert "placeholder" in reason.lower()


def test_reject_pass_statement():
    f = _make_finding("Any Bug", "pass")
    fix, reason = validate_suggested_fix(f, "orig = 1")
    assert fix is None
    assert "placeholder" in reason.lower()


def test_reject_sqli_fstring():
    f = _make_finding("SQL Injection Vulnerability", 'query = f"SELECT * FROM users WHERE name = \'{user}\'"')
    fix, reason = validate_suggested_fix(f)
    assert fix is None
    assert "f-string" in reason.lower()


def test_reject_sqli_execute_fstring():
    f = _make_finding("SQL Injection", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")')
    fix, reason = validate_suggested_fix(f)
    assert fix is None
    assert "f-string" in reason.lower()


def test_reject_inverted_discount():
    f = _make_finding("Inverted Discount Bug", "res = price / (1 - discount / 100)")
    fix, reason = validate_suggested_fix(f)
    assert fix is None
    assert "inverted division" in reason.lower()


def test_reject_zerodivision_without_guard():
    f = _make_finding("ZeroDivision on empty list", "avg = sum(nums) / len(nums)")
    fix, reason = validate_suggested_fix(f)
    assert fix is None
    assert "without an upfront empty check" in reason.lower()


def test_accept_zerodivision_with_guard():
    fix_code = "if not nums:\n    return 0\navg = sum(nums) / len(nums)"
    f = _make_finding("ZeroDivision on empty list", fix_code)
    fix, reason = validate_suggested_fix(f)
    assert fix == fix_code
    assert reason is None


def test_reject_unsafe_eval():
    f = _make_finding("Dangerous eval()", "return eval(user_str)")
    fix, reason = validate_suggested_fix(f)
    assert fix is None
    assert "eval" in reason.lower()
