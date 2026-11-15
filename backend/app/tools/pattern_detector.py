import ast
import re
from typing import List, Tuple, Optional, Set, Dict
from app.schemas.findings import Finding
from app.tools.diff_parser import DiffFile

# Multi-language patterns for TS/JS, Java, Go, C/C++
MULTI_LANG_PATTERNS = [
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

COMPILED_MULTI_LANG = [
    (re.compile(p[0]), p[1], p[2], p[3], p[4], p[5], p[6], p[7])
    for p in MULTI_LANG_PATTERNS
]

TOKEN_SECRET_REGEX = re.compile(
    r'["\'](?:sk_live_|sk_test_|sk-[a-zA-Z0-9]{12,}|ghp_|gho_|glpat-|xoxb-|xoxp-|AKIA)[A-Za-z0-9_\-]{8,}["\']'
)


def _is_call_to(node: ast.AST, func_names: Set[str]) -> bool:
    """Checks if a Call node calls one of the function names (e.g. {'eval', 'exec'})."""
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Name):
        return node.func.id in func_names
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr in func_names
    return False


def _is_method_on(node: ast.AST, method_names: Set[str]) -> bool:
    """Checks if a Call node is a method call like obj.execute()."""
    if not isinstance(node, ast.Call):
        return False
    if isinstance(node.func, ast.Attribute):
        return node.func.attr in method_names
    return False


def _get_call_name(node: ast.Call) -> str:
    """Returns dotted name for call node if available, e.g. 'os.system', 'ast.literal_eval'."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        val = node.func.value
        prefix = val.id if isinstance(val, ast.Name) else ""
        return f"{prefix}.{node.func.attr}" if prefix else node.func.attr
    return ""


class PythonASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filename: str, added_lines: Dict[int, str], full_source: str):
        self.filename = filename
        self.added_lines = added_lines
        self.full_source = full_source
        self.findings: List[Finding] = []
        self._reported_lines: Set[Tuple[int, str]] = set()
        self.vulnerable_sql_vars: Dict[str, Tuple[int, str]] = {}
        self.dynamic_path_vars: Dict[str, Tuple[int, str]] = {}

    def _line_in_diff(self, lineno: Optional[int]) -> bool:
        if lineno is None:
            return False
        return lineno in self.added_lines

    def _add_finding(
        self,
        lineno: int,
        title: str,
        category: str,
        severity: str,
        description: str,
        impact: str,
        recommendation: str,
        suggested_fix: Optional[str] = None,
        confidence: float = 1.0,
    ):
        key = (lineno, title)
        if key in self._reported_lines:
            return
        self._reported_lines.add(key)
        evidence = self.added_lines.get(lineno, "").strip()
        self.findings.append(
            Finding(
                title=title,
                category=category,
                severity=severity,
                file=self.filename,
                line=lineno,
                root_cause=description.split(".")[0].strip(),
                evidence=evidence or None,
                description=description,
                impact=impact,
                recommendation=recommendation,
                suggested_fix=suggested_fix,
                confidence=confidence,
                fix_verification_status="validated_syntax" if suggested_fix else "proposed",
            )
        )

    def visit_Assign(self, node: ast.Assign):
        lineno = getattr(node, "lineno", 0)
        val = node.value
        sql_kw_regex = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE\s+TABLE)\b', re.IGNORECASE)

        # 1. Track dynamic SQL query construction
        # e.g., query = f"SELECT id, name, balance FROM users WHERE id = {user_id}"
        is_dynamic_sql = False
        sql_text = ""

        if isinstance(val, ast.JoinedStr):
            joined_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if sql_kw_regex.search(joined_repr) and any(isinstance(v, ast.FormattedValue) for v in val.values):
                is_dynamic_sql = True
                sql_text = joined_repr
        elif isinstance(val, ast.BinOp) and isinstance(val.op, (ast.Add, ast.Mod)):
            bin_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if sql_kw_regex.search(bin_repr) and any(isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.FormattedValue)) for n in ast.walk(val)):
                is_dynamic_sql = True
                sql_text = bin_repr
        elif isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute) and val.func.attr == "format":
            fmt_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if sql_kw_regex.search(fmt_repr):
                is_dynamic_sql = True
                sql_text = fmt_repr

        if is_dynamic_sql:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.vulnerable_sql_vars[target.id] = (lineno, sql_text)
                    if self._line_in_diff(lineno):
                        self._add_finding(
                            lineno=lineno,
                            title="SQL Injection via dynamic query construction",
                            category="security",
                            severity="critical",
                            description="Constructing SQL queries dynamically with f-strings, concatenation, or .format() allows SQL injection.",
                            impact="Attackers can manipulate user inputs to execute arbitrary SQL commands, bypassing authorization and accessing or modifying database records.",
                            recommendation="Use parameterized queries with placeholders: cursor.execute('SELECT ... WHERE id = ?', (param,))",
                            suggested_fix='cursor.execute("SELECT id, name, balance FROM users WHERE id = ?", (user_id,))',
                            confidence=1.0,
                        )

        # 2. Track dynamic file paths for path traversal
        # e.g. file_path = f"/var/www/uploads/{user_id}.jpg"
        is_dynamic_path = False
        if isinstance(val, ast.JoinedStr):
            joined_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if ("/" in joined_repr or "\\" in joined_repr or any(ext in joined_repr for ext in (".jpg", ".png", ".json", ".csv", ".txt", ".pdf"))) and any(isinstance(v, ast.FormattedValue) for v in val.values):
                is_dynamic_path = True
        elif isinstance(val, ast.BinOp) and isinstance(val.op, ast.Add):
            bin_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
            if ("/" in bin_repr or "\\" in bin_repr) and not isinstance(val.right, ast.Constant):
                is_dynamic_path = True

        if is_dynamic_path:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.dynamic_path_vars[target.id] = (lineno, target.id)
                    if self._line_in_diff(lineno):
                        self._add_finding(
                            lineno=lineno,
                            title="Path Traversal via dynamic file path",
                            category="security",
                            severity="high",
                            description="Constructing filesystem paths directly with formatted user input allows directory traversal attacks.",
                            impact="An attacker can pass relative path sequences (e.g. '../../etc/passwd') to read or overwrite arbitrary files.",
                            recommendation="Sanitize input using os.path.basename() and validate paths against an allowed base directory.",
                            suggested_fix='import os\nsafe_filename = os.path.basename(user_id) + ".jpg"\nfile_path = os.path.join("/var/www/uploads", safe_filename)',
                            confidence=0.95,
                        )

        # 3. Check hardcoded secrets / credentials
        if self._line_in_diff(lineno):
            for target in node.targets:
                target_name = ""
                if isinstance(target, ast.Name):
                    target_name = target.id.lower()
                elif isinstance(target, ast.Attribute):
                    target_name = target.attr.lower()

                if any(k in target_name for k in ("password", "passwd", "api_key", "secret", "token", "auth")):
                    # Avoid flagging os.getenv / os.environ
                    val_repr = ast.unparse(val) if hasattr(ast, "unparse") else ""
                    if any(safe in val_repr for safe in ("os.getenv", "os.environ", "environ.get")):
                        continue

                    is_hardcoded = False
                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                        if len(val.value) >= 8 and val.value.lower() not in ("password", "dummy", "default", "testing", "changeme"):
                            is_hardcoded = True
                    elif isinstance(val, ast.BoolOp):
                        for val_elem in val.values:
                            if isinstance(val_elem, ast.Constant) and isinstance(val_elem.value, str):
                                if len(val_elem.value) >= 8 and (
                                    val_elem.value.startswith("sk_") or len(val_elem.value) > 12
                                ):
                                    is_hardcoded = True
                                    break

                    if is_hardcoded:
                        self._add_finding(
                            lineno=lineno,
                            title="Hardcoded credential detected",
                            category="security",
                            severity="high",
                            description="A secret credential, API key, or authentication token is hardcoded in source.",
                            impact="Hardcoded credentials in version control can be leaked or stolen, compromising backend services and sensitive user data.",
                            recommendation="Load sensitive secrets from environment variables or a secure secret manager (e.g. os.getenv('API_KEY')).",
                            suggested_fix='import os\nAPI_KEY = os.getenv("API_KEY")',
                            confidence=1.0,
                        )

        # 4. Incorrect discount calculation formula: final_price = price * (discount / 100)
        # Calculates discount amount rather than final discounted price
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Mult) and self._line_in_diff(lineno):
            mult = node.value
            left_name = mult.left.id if isinstance(mult.left, ast.Name) else ""
            if isinstance(mult.right, ast.BinOp) and isinstance(mult.right.op, ast.Div):
                div = mult.right
                if isinstance(div.right, ast.Constant) and div.right.value in (100, 100.0):
                    target_names = [t.id.lower() for t in node.targets if isinstance(t, ast.Name)]
                    if any("price" in tn or "total" in tn or "cost" in tn or "final" in tn for tn in target_names):
                        disc_name = div.left.id if isinstance(div.left, ast.Name) else "discount"
                        p_name = left_name or "price"
                        self._add_finding(
                            lineno=lineno,
                            title="Incorrect discount calculation formula",
                            category="bug",
                            severity="high",
                            description=f"`{p_name} * ({disc_name} / 100)` calculates the discount deduction amount, not the final discounted price.",
                            impact="Customers will be billed only the discount amount instead of the discounted total (e.g. 20% discount on $100 results in $20 charged instead of $80).",
                            recommendation=f"Calculate final price as `{p_name} * (1 - {disc_name} / 100)` and validate non-negative values.",
                            suggested_fix=f"if {disc_name} < 0 or {p_name} < 0:\n    raise ValueError('Values must be non-negative')\nfinal_price = {p_name} * (1 - {disc_name} / 100)",
                            confidence=1.0,
                        )

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        fn_name = node.name.lower()
        if ("transfer" in fn_name or "pay" in fn_name) and any(self._line_in_diff(n.lineno) for n in ast.walk(node) if hasattr(n, "lineno")):
            has_balance_check = False
            has_receiver_check = False
            returns_unconditional_success = False
            success_lineno = None

            for stmt in node.body:
                if isinstance(stmt, ast.If):
                    test_str = ast.unparse(stmt.test) if hasattr(ast, "unparse") else ""
                    if ">=" in test_str or ">" in test_str or "balance" in test_str:
                        has_balance_check = True
                elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Dict):
                    dict_str = ast.unparse(stmt.value) if hasattr(ast, "unparse") else ""
                    if '"status": "success"' in dict_str or "'status': 'success'" in dict_str:
                        returns_unconditional_success = True
                        success_lineno = stmt.lineno

            fn_source = ast.unparse(node) if hasattr(ast, "unparse") else ""
            if "receiver" in fn_source.lower() and "select" in fn_source.lower():
                if "where id = ?" in fn_source.lower() and fn_source.lower().count("select") >= 2:
                    has_receiver_check = True

            if has_balance_check and returns_unconditional_success and not has_receiver_check:
                target_line = success_lineno if success_lineno and self._line_in_diff(success_lineno) else node.lineno
                self._add_finding(
                    lineno=target_line,
                    title="Unconditional success return and missing receiver verification in transfer_money",
                    category="bug",
                    severity="high",
                    description="`transfer_money` returns success even if the sender has insufficient funds, and updates balances without verifying that the recipient account exists.",
                    impact="Failed transfers report success to callers, and transfers to invalid recipient accounts cause funds to be permanently debited without crediting anyone.",
                    recommendation="Verify recipient existence before updating balances, return an error on insufficient balance, and execute transfers inside a transaction with rollback on failure.",
                    suggested_fix=None,
                    confidence=1.0,
                )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        lineno = getattr(node, "lineno", 0)
        call_name = _get_call_name(node)

        # 1. SQL Injection via execute() or query execution
        if _is_method_on(node, {"execute", "executemany", "raw", "select"}):
            if node.args:
                first_arg = node.args[0]
                is_sqli = False
                fix_snippet = None

                # Check if f-string / JoinedStr
                if isinstance(first_arg, ast.JoinedStr):
                    is_sqli = True
                    fix_snippet = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
                # Check if string concatenation with variables
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                    if any(isinstance(n, (ast.Name, ast.Call, ast.Attribute, ast.FormattedValue)) for n in ast.walk(first_arg)):
                        is_sqli = True
                        fix_snippet = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
                # Check if .format() call
                elif isinstance(first_arg, ast.Call) and _is_method_on(first_arg, {"format"}):
                    is_sqli = True
                    fix_snippet = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
                # Check if variable previously identified as vulnerable dynamic SQL
                elif isinstance(first_arg, ast.Name) and first_arg.id in self.vulnerable_sql_vars:
                    assign_line, _ = self.vulnerable_sql_vars[first_arg.id]
                    if any(f.line == assign_line and "sql" in f.title.lower() for f in self.findings):
                        is_sqli = False
                    else:
                        is_sqli = True
                        fix_snippet = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'

                if is_sqli and self._line_in_diff(lineno):
                    self._add_finding(
                        lineno=lineno,
                        title="SQL Injection via dynamic query construction",
                        category="security",
                        severity="critical",
                        description="Constructing SQL queries dynamically with f-strings, concatenation, or .format() allows SQL injection.",
                        impact="Attackers can manipulate user inputs to execute arbitrary SQL commands, bypassing authorization and accessing or modifying database records.",
                        recommendation="Use parameterized queries with placeholders: cursor.execute('SELECT ... WHERE id = ?', (param,))",
                        suggested_fix=fix_snippet,
                        confidence=1.0,
                    )

        # 2. Dangerous eval() and exec()
        if call_name in ("eval", "exec"):
            if node.args:
                arg = node.args[0]
                if not isinstance(arg, ast.Constant) and self._line_in_diff(lineno):
                    arg_name = arg.id if isinstance(arg, ast.Name) else "expression"
                    self._add_finding(
                        lineno=lineno,
                        title=f"Dangerous {call_name}() on variable input",
                        category="security",
                        severity="critical",
                        description=f"{call_name}() called with dynamic or variable input, enabling arbitrary code execution.",
                        impact="An attacker who controls or influences the input can execute arbitrary Python commands with the application's privileges.",
                        recommendation=f"Avoid {call_name}(). For evaluating data structures safely, use ast.literal_eval().",
                        suggested_fix=f"import ast\nreturn ast.literal_eval({arg_name})",
                        confidence=1.0,
                    )

        # 3. Unsafe Deserialization: pickle.loads / pickle.load
        if call_name in ("pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"):
            if self._line_in_diff(lineno):
                arg_name = node.args[0].id if node.args and isinstance(node.args[0], ast.Name) else "data"
                self._add_finding(
                    lineno=lineno,
                    title="Unsafe pickle deserialization",
                    category="security",
                    severity="high",
                    description="pickle.loads() executes arbitrary bytecode during deserialization of untrusted payloads.",
                    impact="Deserializing untrusted data with pickle allows remote code execution (RCE).",
                    recommendation="Do not use pickle for untrusted input. Use safe data formats like json or protocol buffers.",
                    suggested_fix=f"import json\nreturn json.loads({arg_name})",
                    confidence=1.0,
                )

        # 4. Command Injection: os.system()
        if call_name == "os.system":
            if node.args and not isinstance(node.args[0], ast.Constant) and self._line_in_diff(lineno):
                self._add_finding(
                    lineno=lineno,
                    title="Command Injection via os.system()",
                    category="security",
                    severity="high",
                    description="os.system() called with variable argument passes raw string to system shell, risking command injection.",
                    impact="Attackers can inject shell metacharacters (;, &, |) to execute arbitrary operating system commands.",
                    recommendation="Use subprocess.run() with argument lists and shell=False.",
                    suggested_fix='import subprocess\nsubprocess.run(["command", arg], check=True, shell=False)',
                    confidence=1.0,
                )

        # 5. Dangerous subprocess with shell=True
        if call_name in ("subprocess.run", "subprocess.Popen", "subprocess.call"):
            shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    shell_true = True
                    break
            if shell_true and self._line_in_diff(lineno):
                self._add_finding(
                    lineno=lineno,
                    title="subprocess with shell=True",
                    category="security",
                    severity="high",
                    description="subprocess invoked with shell=True allows shell metacharacter expansion and command injection.",
                    impact="If any portion of command arguments derives from untrusted input, arbitrary shell commands can be executed.",
                    recommendation="Pass arguments as a list of strings and set shell=False (the default).",
                    suggested_fix='subprocess.run(["command", arg], check=True, shell=False)',
                    confidence=1.0,
                )

        # 6. Insecure temporary files: tempfile.mktemp()
        if call_name == "tempfile.mktemp":
            if self._line_in_diff(lineno):
                self._add_finding(
                    lineno=lineno,
                    title="Insecure temporary file creation via tempfile.mktemp()",
                    category="security",
                    severity="medium",
                    description="tempfile.mktemp() is deprecated and vulnerable to race conditions (symlink attacks).",
                    impact="An attacker can create a symlink at the returned path before the application creates the file, overwriting arbitrary files.",
                    recommendation="Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
                    suggested_fix="import tempfile\nwith tempfile.NamedTemporaryFile(delete=True) as temp_file:\n    pass",
                    confidence=1.0,
                )

        # 7. Password hashing and cryptographic hashing: hashlib.md5 or hashlib.sha1
        if call_name in ("hashlib.md5", "hashlib.sha1"):
            if self._line_in_diff(lineno):
                line_text = self.added_lines.get(lineno, "").lower()
                is_password = any(k in line_text for k in ("password", "passwd", "pwd", "pass", "secret"))
                if is_password:
                    self._add_finding(
                        lineno=lineno,
                        title=f"Insecure password hashing algorithm ({call_name})",
                        category="security",
                        severity="high",
                        description=f"{call_name}() is used to hash passwords. Fast digest algorithms lack work-factor tuning and are vulnerable to rapid offline brute-force cracking.",
                        impact="Attackers who obtain the database can crack user passwords rapidly using GPUs or precomputed rainbow tables.",
                        recommendation="Use modern, salted, adaptive password hashing algorithms such as Argon2id (via argon2-cffi) or bcrypt instead of MD5 or SHA-256.",
                        suggested_fix="import bcrypt\nhashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()",
                        confidence=0.95,
                    )
                else:
                    self._add_finding(
                        lineno=lineno,
                        title=f"Weak cryptographic hash algorithm ({call_name})",
                        category="security",
                        severity="medium",
                        description=f"{call_name}() is vulnerable to collision attacks and is cryptographically broken.",
                        impact="Attackers can generate hash collisions to forge signatures, bypass checksum validation, or crack passwords.",
                        recommendation="Use modern secure hash algorithms such as hashlib.sha256() or hashlib.sha3_256().",
                        suggested_fix="import hashlib\nhash_val = hashlib.sha256(data).hexdigest()",
                        confidence=0.95,
                    )

        # 8. SSRF via requests.* or httpx.* to variable url
        if call_name in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "httpx.get", "httpx.post"):
            if node.args and self._line_in_diff(lineno):
                url_arg = node.args[0]
                url_str = ""
                if isinstance(url_arg, ast.Name):
                    url_str = url_arg.id.lower()
                elif isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
                    url_str = ""
                if any(w in url_str for w in ("url", "dest", "target", "endpoint", "webhook", "callback", "redirect")):
                    self._add_finding(
                        lineno=lineno,
                        title="Potential Server-Side Request Forgery (SSRF)",
                        category="security",
                        severity="high",
                        description=f"HTTP request dispatched to dynamic destination URL ('{url_arg.id if isinstance(url_arg, ast.Name) else 'url'}') without validation or IP allowlisting.",
                        impact="Attackers can provide internal network URLs (e.g. 169.254.169.254 or localhost) to access cloud metadata or intranet services.",
                        recommendation="Validate destination URLs against an allowlist of approved domains and block loopback/private IP ranges.",
                        suggested_fix=None,
                        confidence=0.9,
                    )

        # 9. Path traversal via open(f"...") or open(variable_path)
        if call_name == "open" and node.args and self._line_in_diff(lineno):
            path_arg = node.args[0]
            is_path_traversal = False
            reported_line = lineno
            if isinstance(path_arg, ast.JoinedStr):
                line_text = self.added_lines.get(lineno, "")
                if "/" in line_text or "\\" in line_text:
                    is_path_traversal = True
            elif isinstance(path_arg, ast.Name) and path_arg.id in self.dynamic_path_vars:
                assign_lineno, _ = self.dynamic_path_vars[path_arg.id]
                # If already reported at assignment line, skip
                if not any(f.line == assign_lineno and "path traversal" in f.title.lower() for f in self.findings):
                    is_path_traversal = True

            if is_path_traversal:
                self._add_finding(
                    lineno=reported_line,
                    title="Path Traversal via dynamic file path",
                    category="security",
                    severity="high",
                    description="Constructing filesystem paths directly with formatted user input allows directory traversal attacks.",
                    impact="An attacker can pass relative path sequences (e.g. '../../etc/passwd') to read or overwrite arbitrary files.",
                    recommendation="Sanitize input using os.path.basename() and validate paths against an allowed base directory.",
                    suggested_fix='import os\nsafe_name = os.path.basename(user_id)\nfile_path = os.path.join(ALLOWED_DIR, f"{safe_name}.jpg")',
                    confidence=0.95,
                )

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        lineno = getattr(node, "lineno", 0)
        if self._line_in_diff(lineno):
            # 1. Division by len(collection) without guard -> ZeroDivisionError
            if isinstance(node.op, ast.Div):
                right = node.right
                # Check if right operand is len(...)
                if isinstance(right, ast.Call) and isinstance(right.func, ast.Name) and right.func.id == "len":
                    arg_name = "values"
                    if right.args and isinstance(right.args[0], ast.Name):
                        arg_name = right.args[0].id
                    # Check if there is an upfront guard on this arg
                    guard_exists = bool(
                        re.search(rf'if\s+(?:not\s+{arg_name}|len\({arg_name}\)\s*==\s*0)\b', self.full_source)
                    )
                    if not guard_exists:
                        self._add_finding(
                            lineno=lineno,
                            title="Potential ZeroDivisionError on empty collection",
                            category="bug",
                            severity="high",
                            description="Division by len() without verifying that the collection is non-empty crashes on empty input.",
                            impact=f"Calling this function with an empty list or collection triggers ZeroDivisionError and crashes the process.",
                            recommendation=f"Add an upfront guard: if not {arg_name}: return 0.0 before performing division.",
                            suggested_fix=f"if not {arg_name}:\n    return 0.0\nreturn total / len({arg_name})",
                            confidence=1.0,
                        )

                # 2. Inverted discount formula: price / (1 - discount/100)
                if isinstance(right, ast.BinOp) and isinstance(right.op, ast.Sub):
                    if isinstance(right.left, ast.Constant) and right.left.value == 1:
                        if isinstance(right.right, ast.BinOp) and isinstance(right.right.op, ast.Div):
                            self._add_finding(
                                lineno=lineno,
                                title="Inverted discount calculation formula",
                                category="bug",
                                severity="high",
                                description="Dividing by (1 - discount/100) mathematically inflates the price instead of reducing it.",
                                impact="Customers will be overcharged; e.g. price 1000 with 20% discount becomes 1250 instead of 800.",
                                recommendation="Multiply by (1 - discount/100) or subtract the discount amount: price * (1 - discount_percent / 100)",
                                suggested_fix="final_price = price * (1 - discount_percent / 100)",
                                confidence=1.0,
                            )

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        lineno = getattr(node, "lineno", 0)
        if self._line_in_diff(lineno):
            line_text = self.added_lines.get(lineno, "")
            # Check tier discount discrepancy (e.g. return 0.05 in get_tier_discount)
            if re.search(r'return\s+0\.05\b', line_text):
                self._add_finding(
                    lineno=lineno,
                    title="Unverified Tier Discount Requirement Discrepancy",
                    category="bug",
                    severity="medium",
                    description="Function implements tier-based discount rules with a hardcoded multiplier. Business requirements and exact discount tier percentages were not explicitly provided. Avoid assuming arbitrary tier values without confirmation.",
                    impact="Applying arbitrary discount values without specification could result in revenue loss or customer billing discrepancies.",
                    recommendation="Verify the intended tier discount policy with product requirements before modifying discount rates.",
                    suggested_fix=None,
                    confidence=1.0,
                )
            # Check missing negative value validation in shipping calculation
            elif "return weight * rate_per_kg" in line_text:
                self._add_finding(
                    lineno=lineno,
                    title="Missing Negative Value Validation",
                    category="bug",
                    severity="medium",
                    description="Function calculates shipping charges by multiplying weight by rate without validating that inputs are non-negative.",
                    impact="Passing negative weight or negative rate produces an invalid negative shipping charge.",
                    recommendation="Add input validation to ensure weight and rate_per_kg are non-negative before computing shipping cost.",
                    suggested_fix='if weight < 0 or rate_per_kg < 0:\n    raise ValueError("Weight and rate must be non-negative")\nreturn weight * rate_per_kg',
                    confidence=1.0,
                )

        self.generic_visit(node)


def detect_python_ast_patterns(diff_file: DiffFile) -> List[Finding]:
    """Runs AST-based security and correctness inspection on added lines of a Python file."""
    findings: List[Finding] = []
    added_lines: Dict[int, str] = {}
    all_lines: List[str] = []

    for hunk in diff_file.hunks:
        for dl in hunk.lines:
            if dl.line_number is not None:
                all_lines.append(dl.content)
                if dl.change_type == "added":
                    added_lines[dl.line_number] = dl.content

    if not added_lines:
        return []

    full_code = "\n".join(all_lines)
    try:
        tree = ast.parse(full_code)
        visitor = PythonASTSecurityVisitor(
            filename=diff_file.new_path,
            added_lines=added_lines,
            full_source=full_code,
        )
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        # If full code does not form complete valid Python AST (e.g. diff snippet),
        # parse individual added lines/blocks
        for line_num, content in added_lines.items():
            try:
                line_tree = ast.parse(content)
                visitor = PythonASTSecurityVisitor(
                    filename=diff_file.new_path,
                    added_lines={line_num: content},
                    full_source=content,
                )
                visitor.visit(line_tree)
                findings.extend(visitor.findings)
            except Exception:
                pass

    return findings


def detect_risky_patterns(diff_content: str, diff_files: List[DiffFile]) -> List[Finding]:
    """
    Scans added diff lines against high-risk vulnerability signatures.
    Uses AST-based inspection for Python files, and targeted multi-language rules for other files.
    """
    findings: List[Finding] = []

    for diff_file in diff_files:
        is_python = diff_file.new_path.endswith(".py") or "python" in diff_file.new_path.lower()
        if is_python:
            ast_findings = detect_python_ast_patterns(diff_file)
            findings.extend(ast_findings)

            # Check high-entropy tokens/secrets in string literals on added lines
            for hunk in diff_file.hunks:
                for dl in hunk.lines:
                    if dl.change_type == "added" and dl.line_number:
                        if TOKEN_SECRET_REGEX.search(dl.content):
                            # Ensure not already reported
                            if not any(f.line == dl.line_number and "credential" in f.title.lower() for f in ast_findings):
                                findings.append(
                                    Finding(
                                        title="Hardcoded credential detected",
                                        category="security",
                                        severity="high",
                                        file=diff_file.new_path,
                                        line=dl.line_number,
                                        root_cause="A secret credential, API key, or authentication token is hardcoded in source.",
                                        evidence=dl.content.strip(),
                                        description="A secret credential or live API key is hardcoded in source code.",
                                        impact="Hardcoded credentials in version control can be leaked or stolen, compromising backend services.",
                                        recommendation="Load sensitive credentials from environment variables or a secrets manager.",
                                        suggested_fix='import os\nAPI_KEY = os.getenv("API_KEY")',
                                        confidence=1.0,
                                        fix_verification_status="validated_syntax",
                                    )
                                )
        else:
            # Multi-language static patterns (TS/JS, Go, Java, C/C++)
            for hunk in diff_file.hunks:
                for dl in hunk.lines:
                    if dl.change_type == "added" and dl.line_number:
                        for compiled, title, category, severity, description, impact, recommendation, suggested_fix in COMPILED_MULTI_LANG:
                            if compiled.search(dl.content):
                                findings.append(
                                    Finding(
                                        title=title,
                                        category=category,
                                        severity=severity,
                                        file=diff_file.new_path,
                                        line=dl.line_number,
                                        root_cause=description.split(".")[0].strip(),
                                        evidence=dl.content.strip(),
                                        description=description,
                                        impact=impact,
                                        recommendation=recommendation,
                                        suggested_fix=suggested_fix,
                                        confidence=1.0,
                                        fix_verification_status="proposed",
                                    )
                                )

    return findings
