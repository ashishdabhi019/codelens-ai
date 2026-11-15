import re
from typing import Optional, Tuple
from app.schemas.findings import Finding

PLACEHOLDER_PATTERNS = [
    r'^\s*#\s*(?:TODO|FIXME|WRITE|REPLACE|PUT FIX HERE|YOUR CODE)\b',
    r'^\s*//\s*(?:TODO|FIXME|WRITE|REPLACE|PUT FIX HERE|YOUR CODE)\b',
    r'^\s*pass\s*$',
    r'^\s*\.\.\.\s*$',
]


def normalize_code(code: str) -> str:
    """Strips whitespace, indentation, and trailing semicolons for canonical comparison."""
    if not code:
        return ""
    lines = [line.strip() for line in code.strip().splitlines() if line.strip()]
    return " ".join(lines)


def validate_suggested_fix(
    finding: Finding,
    original_code: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates a suggested code fix against the original code and the issue context.
    Returns:
        (sanitized_fix, rejection_reason)
        If valid: (sanitized_fix, None)
        If invalid: (None, rejection_reason)
    """
    fix = finding.suggested_fix
    if not fix or not fix.strip():
        return None, "No suggested fix was provided."

    cleaned_fix = fix.strip()
    norm_fix = normalize_code(cleaned_fix)

    # Rule 1: Never return the original buggy code as the recommended fix
    if original_code:
        norm_orig = normalize_code(original_code)
        if norm_orig:
            if norm_fix == norm_orig or norm_fix in norm_orig:
                return None, "Suggested fix is identical or equivalent to the original buggy code."
            if norm_orig in norm_fix:
                added_content = norm_fix.replace(norm_orig, "").strip()
                # If no substantial logic (like guards, checks, error handling) was added
                if not any(kw in added_content.lower() for kw in ("if", "try", "except", "raise", "assert", "while", "else", "elif")):
                    return None, "Suggested fix is identical or equivalent to the original buggy code."

    # Rule 2: Reject placeholder comments or empty stubs
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, cleaned_fix, re.IGNORECASE):
            return None, "Suggested fix contains only placeholder text/comments rather than functional code."

    # Rule 3: Check for recurring vulnerability patterns
    lower_title = finding.title.lower()
    lower_desc = finding.description.lower()
    lower_fix = cleaned_fix.lower()

    # 3a. SQL Injection: fix must not retain dynamic string interpolation/formatting
    if "sql" in lower_title or "sql" in lower_desc:
        if re.search(r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\bWHERE\b', cleaned_fix, re.IGNORECASE):
            return None, "Suggested fix still uses an interpolated f-string in the SQL query instead of parameters."
        if re.search(r'\.execute\(\s*f["\']', cleaned_fix, re.IGNORECASE):
            return None, "Suggested fix still passes an unparameterized f-string to execute()."
        if re.search(r'\.execute\(.*?\.format\(', cleaned_fix, re.IGNORECASE):
            return None, "Suggested fix still uses string .format() inside execute() instead of parameters."

    # 3b. Inverted discount formula: fix must not divide by (1 - discount/100)
    if "discount" in lower_title or "discount" in lower_desc:
        if re.search(r'/\s*\(\s*1\s*-\s*\w+\s*/\s*100\s*\)', cleaned_fix):
            return None, "Suggested fix retains the inverted division formula (dividing instead of multiplying)."

    # 3c. ZeroDivision / Empty collection: fix must guard against empty collection
    if "zerodivision" in lower_title or "empty" in lower_desc or "zerodivision" in lower_desc:
        if re.search(r'/\s*len\(', cleaned_fix):
            if not re.search(r'\b(?:if|try|except)\b', cleaned_fix):
                return None, "Suggested fix performs division by len() without an upfront empty check or guard."

    # 3d. Unsafe eval/exec: fix must not call eval() or exec() with variable arguments
    if "eval" in lower_title or "eval" in lower_desc:
        if re.search(r'\beval\s*\([^"\']{3,}\)', cleaned_fix):
            return None, "Suggested fix still uses unsafe eval() on variable input."
    if "exec" in lower_title or "exec" in lower_desc:
        if re.search(r'\bexec\s*\([^"\']{3,}\)', cleaned_fix):
            return None, "Suggested fix still uses unsafe exec() on variable input."

    return cleaned_fix, None
