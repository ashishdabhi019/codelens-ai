"""Tests for Python AST fix validation and fix verification states."""
import pytest
from app.schemas.findings import Finding
from app.tools.fix_validator import validate_suggested_fix, is_valid_python_syntax


def _make_finding(title: str, fix: str, file: str = "app.py") -> Finding:
    return Finding(
        title=title,
        category="security",
        severity="high",
        file=file,
        line=1,
        description="desc",
        impact="impact",
        recommendation="rec",
        suggested_fix=fix,
    )


def test_valid_python_syntax_fix():
    """A syntactically valid Python fix receives 'validated_syntax' status."""
    fix_code = "safe_val = int(user_input)\nreturn safe_val * 2"
    f = _make_finding("Any Bug", fix_code, file="app.py")
    res = validate_suggested_fix(f, "return user_input * 2")
    assert res[0] is not None
    assert res.fix_status == "validated_syntax"


def test_invalid_python_syntax_rejected():
    """A fix with broken Python syntax (e.g. unclosed parentheses) is rejected."""
    bad_syntax = "def broken(\n    return 42"
    f = _make_finding("Any Bug", bad_syntax, file="app.py")
    res = validate_suggested_fix(f, "def orig(): return 0")
    assert res[0] is None
    assert res.fix_status == "rejected"
    assert "syntax" in res[1].lower()


def test_function_signature_alteration_rejected():
    """Altering the number of arguments in a function definition is rejected."""
    orig = "def process(user_id, amount):\n    return amount"
    fix = "def process(user_id):\n    return 0"
    f = _make_finding("Bug", fix, file="app.py")
    res = validate_suggested_fix(f, orig)
    assert res[0] is None
    assert res.fix_status == "rejected"
    assert "signature" in res[1].lower()


def test_missing_import_prepended():
    """Fix using os.getenv without importing os gets 'import os' auto-prepended."""
    fix = 'API_KEY = os.getenv("SECRET")'
    f = _make_finding("Hardcoded Credential", fix, file="config.py")
    res = validate_suggested_fix(f, 'API_KEY = "sk-123456789"')
    assert res[0] is not None
    assert "import os" in res[0]
    assert res.fix_status == "validated_syntax"


def test_non_python_fix_marked_as_proposed():
    """Non-Python fixes that pass checks are marked as 'proposed'."""
    ts_fix = 'const user = await db.query("SELECT * FROM users WHERE id = $1", [id]);'
    f = _make_finding("SQL Injection", ts_fix, file="userRepo.ts")
    res = validate_suggested_fix(f, 'const user = await db.query(`SELECT * FROM users WHERE id = ${id}`);')
    assert res[0] is not None
    assert res.fix_status == "proposed"
