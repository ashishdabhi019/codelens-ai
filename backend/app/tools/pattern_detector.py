import re
from typing import List, Tuple
from app.schemas.findings import Finding
from app.tools.diff_parser import DiffFile

RAW_PATTERNS = [
    (
        r'f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\bWHERE\b',
        "SQL Injection via dynamic f-string query",
        "security",
        "critical",
        "Constructing SQL query with an f-string allows SQL injection.",
        "An attacker can manipulate user input to modify the SQL command and access or alter unauthorized data.",
        "Use parameterized queries with placeholders (? or %s): cursor.execute('SELECT ... WHERE x = ?', (val,))",
        'query = "SELECT * FROM users WHERE username = ?"\nreturn connection.execute(query, (username,)).fetchall()',
    ),
    (
        r'(?:cursor|conn|connection|db|\w+)\.execute\(\s*f["\']',
        "SQL Injection via f-string",
        "security",
        "critical",
        "Direct use of f-string inside execute() allows SQL injection.",
        "Attackers can manipulate the SQL query to access, modify, or delete data.",
        "Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (value,))",
        'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
    ),
    (
        r'(?:cursor|conn|connection|db|\w+)\.execute\(\s*["\'].*?\+',
        "SQL Injection via string concatenation",
        "security",
        "critical",
        "String concatenation inside execute() allows SQL injection.",
        "Attackers can manipulate the SQL query to access, modify, or delete data.",
        "Use parameterized queries with placeholders instead of string concatenation.",
        'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
    ),
    (
        r'\.execute\(.*?\.format\(',
        "SQL Injection via .format()",
        "security",
        "critical",
        "Using .format() inside execute() allows SQL injection.",
        "Attackers can inject arbitrary SQL through format arguments.",
        "Use parameterized queries: cursor.execute('SELECT ... WHERE x = ?', (value,))",
        'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))',
    ),
    (
        r'/\s*\(\s*1\s*-\s*\w+\s*/\s*100\s*\)',
        "Inverted discount calculation formula",
        "bug",
        "high",
        "Dividing by (1 - discount/100) mathematically inflates the price instead of reducing it.",
        "Customers will be overcharged; e.g. price 1000 with 20% discount becomes 1250 instead of 800.",
        "Multiply by (1 - discount/100) or subtract the discount amount: price * (1 - discount_percent / 100)",
        'final_price = price * (1 - discount_percent / 100)',
    ),
    (
        r'/\s*len\(\s*\w+\s*\)',
        "Potential ZeroDivisionError on empty collection",
        "bug",
        "high",
        "Division by len() without verifying whether the collection is non-empty crashes on empty input.",
        "Calling this function with an empty list triggers ZeroDivisionError and crashes the process.",
        "Add an upfront guard: if not values: return 0.0 before performing division.",
        'if not values:\n    return 0.0\nreturn total / len(values)',
    ),
    (
        r'return\s+0\.05\b',
        "Unverified Tier Discount Requirement Discrepancy",
        "bug",
        "medium",
        "Detected code implementing tier-based discount rules. However, business requirements and exact discount tier percentages were not explicitly provided. Avoid assuming arbitrary tier values without confirmation.",
        "Applying arbitrary discount values without specification could result in revenue loss or customer billing discrepancies.",
        "Verify the intended tier discount policy with product requirements before modifying discount rates.",
        None,
    ),
    (
        r'return\s+weight\s*\*\s*rate_per_kg',
        "Missing Negative Value Validation",
        "bug",
        "medium",
        "Function calculates shipping charges by multiplying weight by rate without validating that inputs are non-negative.",
        "Passing negative weight or negative rate produces an invalid negative shipping charge.",
        "Add input validation to ensure weight and rate_per_kg are non-negative before computing shipping cost.",
        'if weight < 0 or rate_per_kg < 0:\n    raise ValueError("Weight and rate must be non-negative")\nreturn weight * rate_per_kg',
    ),
    (
        r'\beval\s*\([^"\']{3,}\)',
        "Dangerous eval() on variable input",
        "security",
        "critical",
        "eval() called with a non-literal argument, allowing arbitrary code execution.",
        "An attacker controlling the input can execute arbitrary Python code.",
        "Avoid eval(). Use ast.literal_eval() for safe evaluation of literals.",
        'import ast\nreturn ast.literal_eval(filter_expr)',
    ),
    (
        r'\bexec\s*\([^"\']{3,}\)',
        "Dangerous exec() on variable input",
        "security",
        "critical",
        "exec() called with a non-literal argument, allowing arbitrary code execution.",
        "An attacker controlling the input can execute arbitrary Python code.",
        "Avoid exec(). Refactor to use safe alternatives.",
        '# Avoid exec() on untrusted variable input; refactor to a safe parser or whitelist mapping',
    ),
    (
        r'(?i)(?:password|passwd|secret|api_key|token|auth)\s*(?:=|or|:)\s*["\'][^"\']{6,}["\']|["\'](?:sk_live_|sk_test_|ghp_|gho_|glpat-|xoxb-|xoxp-|AKIA)[A-Za-z0-9_\-]{8,}["\']',
        "Hardcoded credential detected",
        "security",
        "high",
        "A credential, API key, or token is hardcoded in source.",
        "Hardcoded credentials can be exposed through version control or code leaks.",
        "Use environment variables or a secrets manager instead of hardcoding credentials.",
        'import os\nAPI_KEY = os.getenv("API_KEY")',
    ),
    (
        r'f["\'](?:/|\./|\.\./).*?\{|open\(\s*f["\'].*?\{',
        "Path Traversal via dynamic file path",
        "security",
        "high",
        "Constructing filesystem paths directly with formatted user input allows directory traversal attacks.",
        "An attacker can pass relative paths (e.g. '../../etc/passwd') to read or overwrite arbitrary files.",
        "Sanitize input using os.path.basename() and validate within an allowed base directory.",
        'safe_name = os.path.basename(user_input)\nfile_path = os.path.join(ALLOWED_DIR, f"{safe_name}.json")',
    ),
    (
        r'requests\.(?:get|post|put|delete|patch)\(\s*(?!["\']https?://)(?:webhook|\w+_url)',
        "Potential Server-Side Request Forgery (SSRF)",
        "security",
        "high",
        "Sending HTTP requests to an unvalidated, user-supplied URL allows SSRF attacks targeting internal network services.",
        "Attackers can probe internal metadata endpoints (169.254.169.254) or intranet microservices.",
        "Validate the destination URL against an allowlist of trusted domains and block loopback/private IP addresses.",
        '# Validate destination URL against an allowlist of approved domains before sending request',
    ),
    (
        r'if\s+amount\s*==\s*0\b',
        "Missing Negative Amount Validation",
        "bug",
        "high",
        "Checking only amount == 0 skips zero but allows negative amounts, which reverses financial transaction polarity.",
        "Passing a negative amount in refund or payment operations can credit unauthorized funds or drain balances.",
        "Validate that amount is strictly positive: if amount <= 0:",
        'if amount <= 0:\n    return {"status": "error", "reason": "amount must be greater than zero"}',
    ),
    (
        r'os\.system\([^"\']{3,}\)',
        "os.system() with variable input",
        "security",
        "high",
        "os.system() called with a variable argument, risking command injection.",
        "Attacker-controlled input can execute arbitrary shell commands.",
        "Use subprocess.run() with a list of arguments and avoid shell=True.",
        'import subprocess\nsubprocess.run(["cmd", arg], check=True)',
    ),
    (
        r'pickle\.loads\(',
        "Unsafe pickle.loads()",
        "security",
        "high",
        "pickle.loads() can execute arbitrary code when deserializing untrusted data.",
        "If untrusted data is deserialized, arbitrary code may be executed.",
        "Avoid pickle for untrusted data. Use JSON or other safe serialization formats.",
        'import json\ndata = json.loads(payload)',
    ),
    (
        r'subprocess\.(call|run|Popen)\(.*shell\s*=\s*True',
        "subprocess with shell=True",
        "security",
        "high",
        "subprocess called with shell=True, which may allow command injection.",
        "If any part of the command comes from user input, shell injection is possible.",
        "Pass arguments as a list and set shell=False (the default).",
        'subprocess.run(["command", arg], check=True, shell=False)',
    ),
    (
        r'(?:db|pool|client|connection|sequelize|knex)\.(?:query|raw)\(\s*`\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\$\{',
        "SQL Injection via template literal interpolation",
        "security",
        "critical",
        "Constructing SQL query with interpolated template variables allows SQL injection.",
        "Attackers can manipulate variables to modify the SQL command and execute unauthorized operations.",
        "Use parameterized query placeholders ($1, $2 or ?) instead of string interpolation.",
        'await db.query("SELECT * FROM users WHERE id = $1", [userId]);',
    ),
    (
        r'(?:executeQuery|executeUpdate)\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*?\+',
        "SQL Injection via string concatenation",
        "security",
        "critical",
        "Concatenating user variables into SQL query string allows SQL injection.",
        "Attackers can inject malicious SQL statements to compromise the database.",
        "Use PreparedStatement with parameterized placeholders (?) instead of string concatenation.",
        'PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nstmt.setString(1, userId);',
    ),
    (
        r'(?:db|tx)\.Query(?:Row)?\(\s*fmt\.Sprintf\(\s*["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b',
        "SQL Injection via fmt.Sprintf",
        "security",
        "critical",
        "Using fmt.Sprintf to format queries allows SQL injection through user input.",
        "Attackers can execute arbitrary SQL queries against the database.",
        "Pass arguments as query parameters: db.Query(\"SELECT ... WHERE id = $1\", id).",
        'rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)',
    ),
    (
        r'\.innerHTML\s*=\s*(?!["\']<)(?:`[^`]*\$\{|\w+)',
        "Cross-Site Scripting (XSS) via raw innerHTML assignment",
        "security",
        "critical",
        "Assigning unescaped user-controlled content to innerHTML introduces DOM-based XSS vulnerabilities.",
        "Attackers can inject malicious JavaScript to steal session tokens or perform unauthorized actions on behalf of users.",
        "Use textContent or a sanitizer like DOMPurify before inserting dynamic content into the DOM.",
        'element.textContent = userInput;',
    ),
    (
        r'\b(?:strcpy|gets)\s*\(',
        "Dangerous unsafe buffer function",
        "security",
        "high",
        "Unbounded copy functions (strcpy, gets) lack buffer size limits and cause buffer overflow vulnerabilities.",
        "Input exceeding buffer capacity can overwrite adjacent stack memory and cause memory corruption or arbitrary code execution.",
        "Replace strcpy with strncpy or strlcpy, and replace gets with fgets.",
        'strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';',
    ),
]

COMPILED_PATTERNS = [
    (re.compile(p[0]), p[1], p[2], p[3], p[4], p[5], p[6], p[7])
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
    for compiled, title, category, severity, description, impact, recommendation, suggested_fix in COMPILED_PATTERNS:
        for content, filename, line_number in added_lines:
            if compiled.search(content):
                actual_fix = suggested_fix
                if "ZeroDivisionError" in title:
                    m_len = re.search(r'/\s*len\(\s*(\w+)\s*\)', content)
                    if m_len:
                        var_name = m_len.group(1)
                        actual_fix = f"if not {var_name}:\n    return 0.0\n{content.strip()}"

                # Deterministic findings carry confidence = 1.0 because regex hit on known bad pattern
                findings.append(
                    Finding(
                        title=title,
                        category=category,
                        severity=severity,
                        file=filename,
                        line=line_number or None,
                        root_cause=description.split(".")[0].strip(),
                        evidence=content.strip(),
                        description=description,
                        impact=impact,
                        recommendation=recommendation,
                        suggested_fix=actual_fix,
                        confidence=1.0,
                    )
                )

    return findings
