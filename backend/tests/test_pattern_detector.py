"""Tests for detect_risky_patterns."""
import pytest
from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns


def _make_diff(added_line: str, filename: str = "test.py") -> str:
    return (
        f"diff --git a/{filename} b/{filename}\n"
        f"index 0000001..0000002 100644\n"
        f"--- a/{filename}\n"
        f"+++ b/{filename}\n"
        f"@@ -1,2 +1,3 @@\n"
        f" existing = 1\n"
        f"+{added_line}\n"
        f" pass\n"
    )


def test_sql_injection_fstring():
    diff = _make_diff(
        "cursor.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")"
    )
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)
    assert any(f.severity == "critical" for f in findings)
    assert all(f.confidence >= 0.9 for f in findings)


def test_sql_injection_concatenation():
    diff = _make_diff(
        'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
    )
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL" in f.title for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_hardcoded_password():
    diff = _make_diff('password = "supersecret123"')
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("credential" in f.title.lower() or "Hardcoded" in f.title for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_hardcoded_api_key():
    diff = _make_diff('api_key = "sk-abc123xyz789longkey"')
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any(f.severity in ("high", "critical") for f in findings)


def test_eval_on_variable():
    diff = _make_diff("result = eval(user_input)")
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("eval" in f.title.lower() for f in findings)
    assert any(f.severity == "critical" for f in findings)


def test_pickle_loads():
    diff = _make_diff("obj = pickle.loads(data)")
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("pickle" in f.title.lower() for f in findings)
    assert any(f.severity == "high" for f in findings)


def test_clean_code_no_findings():
    diff = _make_diff("result = a + b")
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert findings == []


def test_findings_reference_correct_file():
    diff = _make_diff('password = "hunter2abc"', filename="auth.py")
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert all(f.file == "auth.py" for f in findings)
