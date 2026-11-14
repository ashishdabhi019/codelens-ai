import re
from typing import List, Tuple
from app.schemas.findings import Finding
from app.tools.diff_parser import DiffFile

RAW_PATTERNS = [
    (
        r'cursor\.execute\(f["\']',
        "SQL Injection via f-string",
        "security",
        "critical",
        "Direct use of f-string inside cursor.execute() allows SQL injection.",
        "Attackers can manipulate the SQL query to access, modify, or delete data.",
        "Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (value,))",
    ),
    (
        r'cursor\.execute\(["\'].*?\+',
        "SQL Injection via string concatenation",
        "security",
        "critical",
        "String concatenation inside cursor.execute() allows SQL injection.",
        "Attackers can manipulate the SQL query to access, modify, or delete data.",
        "Use parameterized queries with placeholders instead of string concatenation.",
    ),
    (
        r'\.execute\(.*?\.format\(',
        "SQL Injection via .format()",
        "security",
        "critical",
        "Using .format() inside execute() allows SQL injection.",
        "Attackers can inject arbitrary SQL through format arguments.",
        "Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (value,))",
    ),
    (
        r'\beval\s*\([^"\']{3,}\)',
        "Dangerous eval() on variable input",
        "security",
        "critical",
        "eval() called with a non-literal argument, allowing arbitrary code execution.",
        "An attacker controlling the input can execute arbitrary Python code.",
        "Avoid eval(). Use ast.literal_eval() for safe evaluation of literals.",
    ),
    (
        r'\bexec\s*\([^"\']{3,}\)',
        "Dangerous exec() on variable input",
        "security",
        "critical",
        "exec() called with a non-literal argument, allowing arbitrary code execution.",
        "An attacker controlling the input can execute arbitrary Python code.",
        "Avoid exec(). Refactor to use safe alternatives.",
    ),
    (
        r'(?i)(?:password|passwd|secret|api_key|token)\s*=\s*["\'][^"\']{6,}["\']',
        "Hardcoded credential detected",
        "security",
        "high",
        "A credential (password, secret, API key, or token) is hardcoded in source.",
        "Hardcoded credentials can be exposed through version control or code leaks.",
        "Use environment variables or a secrets manager instead of hardcoding credentials.",
    ),
    (
        r'os\.system\([^"\']{3,}\)',
        "os.system() with variable input",
        "security",
        "high",
        "os.system() called with a variable argument, risking command injection.",
        "Attacker-controlled input can execute arbitrary shell commands.",
        "Use subprocess.run() with a list of arguments and avoid shell=True.",
    ),
    (
        r'pickle\.loads\(',
        "Unsafe pickle.loads()",
        "security",
        "high",
        "pickle.loads() can execute arbitrary code when deserializing untrusted data.",
        "If untrusted data is deserialized, arbitrary code may be executed.",
        "Avoid pickle for untrusted data. Use JSON or other safe serialization formats.",
    ),
    (
        r'subprocess\.(call|run|Popen)\(.*shell\s*=\s*True',
        "subprocess with shell=True",
        "security",
        "high",
        "subprocess called with shell=True, which may allow command injection.",
        "If any part of the command comes from user input, shell injection is possible.",
        "Pass arguments as a list and set shell=False (the default).",
    ),
]

COMPILED_PATTERNS = [
    (re.compile(p[0]), p[1], p[2], p[3], p[4], p[5], p[6])
    for p in RAW_PATTERNS
]


def detect_risky_patterns(diff_content: str, diff_files: List[DiffFile]) -> List[Finding]:
    """Scans added diff lines against high-risk vulnerability signatures."""
    findings: List[Finding] = []

    # Important: only inspect ADDED lines. If a line is being deleted or is surrounding context,
    # raising an alert here would create noisy false positives on issues the developer is actively removing.
    added_lines: List[Tuple[str, str, int]] = []
    for diff_file in diff_files:
        for hunk in diff_file.hunks:
            for dl in hunk.lines:
                if dl.change_type == "added":
                    added_lines.append((dl.content, diff_file.new_path, dl.line_number or 0))

    # Match each added line against pre-compiled high-risk security rules
    for compiled, title, category, severity, description, impact, recommendation in COMPILED_PATTERNS:
        for content, filename, line_number in added_lines:
            if compiled.search(content):
                # Deterministic findings carry confidence = 1.0 because regex hit on known bad pattern
                findings.append(
                    Finding(
                        title=title,
                        category=category,
                        severity=severity,
                        file=filename,
                        line=line_number or None,
                        description=description,
                        impact=impact,
                        recommendation=recommendation,
                        confidence=1.0,
                    )
                )

    return findings
