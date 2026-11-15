import ast
import re
import textwrap
from typing import Optional, Tuple
from app.schemas.findings import Finding

PLACEHOLDER_PATTERNS = [
    r'^\s*#\s*(?:TODO|FIXME|WRITE|REPLACE|PUT FIX HERE|YOUR CODE)\b',
    r'^\s*//\s*(?:TODO|FIXME|WRITE|REPLACE|PUT FIX HERE|YOUR CODE)\b',
    r'^\s*pass\s*$',
    r'^\s*\.\.\.\s*$',
]

COMMON_STD_MODULES = {
    "os": ["os.getenv", "os.environ", "os.path"],
    "json": ["json.loads", "json.dumps", "json.load", "json.dump"],
    "ast": ["ast.literal_eval"],
    "re": ["re.search", "re.match", "re.findall", "re.sub", "re.compile"],
    "sys": ["sys.exit", "sys.argv"],
    "subprocess": ["subprocess.run", "subprocess.Popen", "subprocess.call"],
    "math": ["math.isclose", "math.isnan", "math.sqrt"],
}


class ValidationResult(tuple):
    """
    Subclasses 2-tuple for backwards compatibility (sanitized_fix, rejection_reason),
    while also exposing .fix_status ('validated_syntax', 'passed_tests', 'proposed', 'rejected').
    """
    def __new__(cls, sanitized_fix: Optional[str], rejection_reason: Optional[str], fix_status: str = "proposed"):
        return super().__new__(cls, (sanitized_fix, rejection_reason))

    def __init__(self, sanitized_fix: Optional[str], rejection_reason: Optional[str], fix_status: str = "proposed"):
        self.sanitized_fix = sanitized_fix
        self.rejection_reason = rejection_reason
        self.fix_status = fix_status


def normalize_code(code: str) -> str:
    """Strips whitespace, indentation, and trailing semicolons for canonical comparison."""
    if not code:
        return ""
    lines = [line.strip().rstrip(";") for line in code.strip().splitlines() if line.strip()]
    return " ".join(lines)


def is_valid_python_syntax(code: str) -> bool:
    """Checks whether the code snippet is valid Python syntax, handling partial/indented snippets."""
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        pass

    try:
        ast.parse(textwrap.dedent(code))
        return True
    except SyntaxError:
        pass

    # Handles bare returns or yields inside code snippets
    try:
        indented = "\n".join("    " + line for line in code.splitlines())
        ast.parse(f"def _validator_dummy_fn():\n{indented}")
        return True
    except SyntaxError:
        return False


def check_missing_python_imports(code: str) -> str:
    """
    Checks if common standard library modules are used without being imported,
    and prepends the required import statements to make the fix self-contained.
    """
    needed_imports = []
    for mod, prefixes in COMMON_STD_MODULES.items():
        if any(prefix in code for prefix in prefixes):
            import_regex = rf"(?:^|\n)\s*(?:import\s+{mod}\b|from\s+{mod}\s+import\b)"
            if not re.search(import_regex, code):
                needed_imports.append(f"import {mod}")

    if needed_imports:
        return "\n".join(needed_imports) + "\n" + code
    return code


def check_function_signature_preserved(orig: str, fix: str) -> Tuple[bool, Optional[str]]:
    """
    If both original code and fix declare a function, verify parameter counts are compatible.
    """
    try:
        tree_orig = ast.parse(textwrap.dedent(orig))
        tree_fix = ast.parse(textwrap.dedent(fix))
        fn_orig = next((n for n in ast.walk(tree_orig) if isinstance(n, ast.FunctionDef)), None)
        fn_fix = next((n for n in ast.walk(tree_fix) if isinstance(n, ast.FunctionDef)), None)

        if fn_orig and fn_fix:
            args_orig = [a.arg for a in fn_orig.args.args]
            args_fix = [a.arg for a in fn_fix.args.args]
            if len(args_orig) != len(args_fix):
                return False, f"Function signature altered: original had {len(args_orig)} args, fix has {len(args_fix)}."
    except Exception:
        pass
    return True, None


def validate_suggested_fix(
    finding: Finding,
    original_code: Optional[str] = None,
    file_path: Optional[str] = None,
) -> ValidationResult:
    """
    Validates a suggested code fix against original code, syntax rules, and security constraints.
    Returns ValidationResult tuple: (sanitized_fix, rejection_reason) with .fix_status
    """
    fix = finding.suggested_fix
    if not fix or not fix.strip():
        return ValidationResult(None, "No suggested fix was provided.", "rejected")

    cleaned_fix = fix.strip()
    norm_fix = normalize_code(cleaned_fix)

    # Rule 1: Never return the original buggy code as the recommended fix
    if original_code:
        norm_orig = normalize_code(original_code)
        if norm_orig:
            if norm_fix == norm_orig or norm_fix in norm_orig:
                return ValidationResult(None, "Suggested fix is identical or equivalent to the original buggy code.", "rejected")
            if norm_orig in norm_fix:
                added_content = norm_fix.replace(norm_orig, "").strip()
                # If no substantial logic (like guards, checks, error handling) was added
                if not any(kw in added_content.lower() for kw in ("if", "try", "except", "raise", "assert", "while", "else", "elif")):
                    return ValidationResult(None, "Suggested fix is identical or equivalent to the original buggy code.", "rejected")

    # Rule 2: Reject placeholder comments or empty stubs
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix contains only placeholder text/comments rather than functional code.", "rejected")

    # Rule 3: Check for recurring vulnerability patterns inside the fix itself
    lower_title = finding.title.lower()
    lower_desc = finding.description.lower()

    # 3a. SQL Injection: fix must not retain dynamic string interpolation/formatting
    if "sql" in lower_title or "sql" in lower_desc:
        if re.search(r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\bWHERE\b', cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix still uses an interpolated f-string in the SQL query instead of parameters.", "rejected")
        if re.search(r'\.execute\(\s*f["\']', cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix still passes an unparameterized f-string to execute().", "rejected")
        if re.search(r'\.execute\(.*?\.format\(', cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix still uses string .format() inside execute() instead of parameters.", "rejected")
        if re.search(r'`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\$\{', cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix still uses template string interpolation in SQL query instead of parameterized query.", "rejected")
        if re.search(r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\+\s*\w+', cleaned_fix, re.IGNORECASE):
            return ValidationResult(None, "Suggested fix still uses string concatenation in SQL query instead of parameters.", "rejected")

    # 3b. Inverted discount formula: fix must not divide by (1 - discount/100)
    if "discount" in lower_title or "discount" in lower_desc:
        if re.search(r'/\s*\(\s*1\s*-\s*\w+\s*/\s*100\s*\)', cleaned_fix):
            return ValidationResult(None, "Suggested fix retains the inverted division formula (dividing instead of multiplying).", "rejected")

    # 3c. ZeroDivision / Empty collection: fix must guard against empty collection
    if "zerodivision" in lower_title or "empty" in lower_desc or "zerodivision" in lower_desc:
        if re.search(r'/\s*(?:len\(|\.length\b)', cleaned_fix):
            if not re.search(r'\b(?:if|try|except|catch)\b', cleaned_fix):
                return ValidationResult(None, "Suggested fix performs division by collection size without an upfront empty check or guard.", "rejected")

    # 3d. Unsafe eval/exec: fix must not call eval() or exec() with variable arguments
    if "eval" in lower_title or "eval" in lower_desc:
        if re.search(r'\beval\s*\([^"\']{3,}\)', cleaned_fix):
            return ValidationResult(None, "Suggested fix still uses unsafe eval() on variable input.", "rejected")
        if re.search(r'\bnew\s+Function\s*\(', cleaned_fix):
            return ValidationResult(None, "Suggested fix still uses dynamic Function constructor on untrusted input.", "rejected")
    if "exec" in lower_title or "exec" in lower_desc:
        if re.search(r'\bexec\s*\([^"\']{3,}\)', cleaned_fix):
            return ValidationResult(None, "Suggested fix still uses unsafe exec() on variable input.", "rejected")

    # 3e. Cross-Site Scripting (XSS): fix must not assign raw unescaped input to innerHTML
    if "xss" in lower_title or "xss" in lower_desc:
        if re.search(r'\.(?:innerHTML|outerHTML)\s*=\s*(?:`[^`]*\$\{|\w+)', cleaned_fix):
            return ValidationResult(None, "Suggested fix still assigns unsanitized variable directly to innerHTML instead of textContent or sanitization.", "rejected")

    # Determine file target language
    target_path = file_path or finding.file or ""
    is_python = target_path.endswith(".py") or "python" in target_path.lower()

    if is_python:
        # Check Python syntax via AST
        if not is_valid_python_syntax(cleaned_fix):
            return ValidationResult(None, "Suggested fix contains invalid Python syntax.", "rejected")

        # Check function signature preservation if relevant
        if original_code:
            preserved, sig_reason = check_function_signature_preserved(original_code, cleaned_fix)
            if not preserved:
                return ValidationResult(None, sig_reason, "rejected")

        # Check missing standard library imports (e.g. os, ast, json)
        cleaned_fix = check_missing_python_imports(cleaned_fix)
        return ValidationResult(cleaned_fix, None, "validated_syntax")

    # For other languages (TS, JS, Go, Java, C, etc.)
    return ValidationResult(cleaned_fix, None, "proposed")
