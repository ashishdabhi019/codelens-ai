"""
Positive and negative regression tests for all 12 vulnerability and bug categories.

Categories tested:
1. SQL Injection (AST source-to-sink)
2. Hardcoded Credentials & Secrets
3. Dangerous eval() and exec()
4. Unsafe Deserialization (pickle)
5. ZeroDivisionError & Arithmetic Logic
6. Insecure Cryptographic Hash Algorithms (MD5, SHA-1)
7. Server-Side Request Forgery (SSRF)
8. Path Traversal (Source-to-sink file operations)
9. Command Injection (os.system, subprocess with shell=True)
10. Cross-Site Scripting (DOM XSS via innerHTML)
11. Buffer Overflow (C strcpy)
12. Race Conditions & Payment Integrity (webhook before idempotency, bank transfers)
"""
import pytest
from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns


def _diff_from_code(code: str, filename: str = "app.py") -> str:
    lines = code.strip().splitlines()
    header = [
        f"diff --git a/{filename} b/{filename}",
        "--- /dev/null",
        f"+++ b/{filename}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    return "\n".join(header + [f"+{l}" for l in lines]) + "\n"


def _run_detector(code: str, filename: str = "app.py"):
    diff = _diff_from_code(code, filename)
    files = parse_git_diff(diff)
    return detect_risky_patterns(diff, files)


# 1. SQL Injection
def test_sqli_positive():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")'
    findings = _run_detector(code)
    assert any("sql" in f.title.lower() for f in findings)


def test_sqli_negative_parameterized():
    code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    findings = _run_detector(code)
    assert not any("sql" in f.title.lower() for f in findings)


def test_sqli_negative_unexecuted_assignment():
    code = """def report(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return "Report ready"
"""
    findings = _run_detector(code)
    assert not any("sql" in f.title.lower() for f in findings)


# 2. Hardcoded Credentials
def test_credential_positive():
    code = 'stripe_key = "sk_live_998877665544332211"'
    findings = _run_detector(code)
    assert any("credential" in f.title.lower() for f in findings)


def test_credential_negative_env_var():
    code = 'stripe_key = os.getenv("STRIPE_API_KEY")'
    findings = _run_detector(code)
    assert not any("credential" in f.title.lower() for f in findings)


# 3. Dangerous eval / exec
def test_eval_positive():
    code = "res = eval(user_input)"
    findings = _run_detector(code)
    assert any("eval" in f.title.lower() for f in findings)


def test_eval_negative_literal_eval():
    code = "import ast\nres = ast.literal_eval(user_input)"
    findings = _run_detector(code)
    assert not any("eval" in f.title.lower() for f in findings)


# 4. Unsafe Deserialization
def test_pickle_positive():
    code = "data = pickle.loads(raw_bytes)"
    findings = _run_detector(code)
    assert any("pickle" in f.title.lower() for f in findings)


def test_pickle_negative_json():
    code = "import json\ndata = json.loads(raw_text)"
    findings = _run_detector(code)
    assert not any("pickle" in f.title.lower() for f in findings)


# 5. ZeroDivision & Arithmetic
def test_zerodivision_positive_unguarded():
    code = """def avg(items):
    total = sum(items)
    return total / len(items)
"""
    findings = _run_detector(code)
    assert any("zerodivision" in f.title.lower() for f in findings)


def test_zerodivision_negative_guarded():
    code = """def avg(items):
    if not items:
        return 0.0
    return sum(items) / len(items)
"""
    findings = _run_detector(code)
    assert not any("zerodivision" in f.title.lower() for f in findings)


def test_zerodivision_negative_multiplication():
    code = "cashback = total_spend * 0.125"
    findings = _run_detector(code)
    assert not any("zerodivision" in f.title.lower() for f in findings)


# 6. Insecure Cryptographic Hash
def test_crypto_positive_md5():
    code = "hashed = hashlib.md5(password.encode()).hexdigest()"
    findings = _run_detector(code)
    assert any("md5" in f.title.lower() or "password" in f.title.lower() for f in findings)


def test_crypto_negative_bcrypt():
    code = "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()"
    findings = _run_detector(code)
    assert not any("algorithm" in f.title.lower() for f in findings)


# 7. SSRF
def test_ssrf_positive_dynamic_url():
    code = "resp = requests.post(webhook_url, json=data)"
    findings = _run_detector(code)
    assert any("ssrf" in f.title.lower() for f in findings)


def test_ssrf_negative_static_url():
    code = 'resp = requests.post("https://api.payments.internal/webhook", json=data)'
    findings = _run_detector(code)
    assert not any("ssrf" in f.title.lower() for f in findings)


# 8. Path Traversal
def test_path_traversal_positive_sink():
    code = """def read_file(user_id):
    path = f"/var/data/{user_id}.json"
    with open(path, "r") as f:
        return f.read()
"""
    findings = _run_detector(code)
    assert any("path traversal" in f.title.lower() for f in findings)


def test_path_traversal_negative_unexecuted_assignment():
    code = """def format_filename(user_id):
    filename = f"/var/data/{user_id}.json"
    return "Calculated"
"""
    findings = _run_detector(code)
    assert not any("path traversal" in f.title.lower() for f in findings)


# 9. Command Injection
def test_command_injection_positive_os_system():
    code = 'os.system("rm -rf " + folder_name)'
    findings = _run_detector(code)
    assert any("command injection" in f.title.lower() or "os.system" in f.title.lower() for f in findings)


def test_command_injection_negative_subprocess_list():
    code = 'subprocess.run(["ls", "-l", folder_name], shell=False, check=True)'
    findings = _run_detector(code)
    assert not any("command injection" in f.title.lower() or "subprocess" in f.title.lower() for f in findings)


# 10. Cross-Site Scripting (DOM XSS)
def test_xss_positive_innerhtml():
    code = "element.innerHTML = userProvidedHtml;"
    findings = _run_detector(code, filename="component.ts")
    assert any("xss" in f.title.lower() or "cross-site" in f.title.lower() for f in findings)


def test_xss_negative_textcontent():
    code = "element.textContent = userProvidedText;"
    findings = _run_detector(code, filename="component.ts")
    assert not any("xss" in f.title.lower() for f in findings)


# 11. Buffer Overflow
def test_buffer_overflow_positive_strcpy():
    code = "strcpy(dest, src);"
    findings = _run_detector(code, filename="buffer.c")
    assert any("buffer" in f.title.lower() or "strcpy" in f.title.lower() for f in findings)


def test_buffer_overflow_negative_strncpy():
    code = "strncpy(dest, src, sizeof(dest) - 1);"
    findings = _run_detector(code, filename="buffer.c")
    assert not any("buffer" in f.title.lower() for f in findings)


# 12. Race Conditions & Payment Integrity
def test_race_condition_positive():
    code = """class PaymentService:
    def refund(self, tx_id, amount):
        requests.post("https://api.external/refund", json={"tx": tx_id})
        if tx_id in self.processed:
            raise ValueError("Duplicate")
        self.processed.add(tx_id)
"""
    findings = _run_detector(code)
    assert any("race condition" in f.title.lower() or "duplicate" in f.title.lower() for f in findings)


def test_race_condition_negative_synchronized():
    code = """class PaymentService:
    def refund(self, tx_id, amount):
        with self.lock:
            requests.post("https://api.external/refund", json={"tx": tx_id})
            if tx_id in self.processed:
                raise ValueError("Duplicate")
            self.processed.add(tx_id)
"""
    findings = _run_detector(code)
    assert not any("race condition" in f.title.lower() for f in findings)
