from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge
from app.schemas.findings import ReviewResult


def test_calculator_22_lines_demo_scenario():
    """Verifies finding line numbers and fix behaviors for calculator.py regression case."""
    with open("sample_diffs/python_logic_bug.diff") as f:
        diff_text = f.read()

    diff_files = parse_git_diff(diff_text)
    assert len(diff_files) == 1
    assert diff_files[0].new_path == "calculator.py"

    deterministic = detect_risky_patterns(diff_text, diff_files)
    res = validate_and_merge(
        ReviewResult(
            overall_status="changes_requested",
            risk_level="high",
            summary="Test summary",
            files_reviewed=1,
        ),
        deterministic,
        diff_files=diff_files,
    )

    findings_by_line = {f.line: f for f in res.findings}

    # 1. Line 3: Inverted discount formula with copyable fix
    assert 3 in findings_by_line
    f3 = findings_by_line[3]
    assert "discount" in f3.title.lower()
    assert f3.suggested_fix is not None
    assert "price *" in f3.suggested_fix

    # 2. Line 9: Empty collection crash with safe guard
    assert 9 in findings_by_line
    f9 = findings_by_line[9]
    assert "zerodivision" in f9.title.lower() or "empty" in f9.title.lower()
    assert f9.suggested_fix is not None
    assert "if not values:" in f9.suggested_fix

    # 3. Line 14: Tier discount discrepancy without arbitrary numbers
    assert 14 in findings_by_line
    f14 = findings_by_line[14]
    assert "tier" in f14.title.lower() or "discount" in f14.title.lower()
    # Must NOT invent arbitrary constant numbers
    assert f14.suggested_fix is None

    # 4. Line 22: Negative value validation
    assert 22 in findings_by_line
    f22 = findings_by_line[22]
    assert "negative" in f22.title.lower()
    assert f22.suggested_fix is not None
    assert "weight < 0" in f22.suggested_fix
