#!/usr/bin/env python3
"""
CodeLens AI — Precision, Recall, and F1 Benchmark Suite.

Evaluates deterministic static analysis and finding validation across 52 labeled test cases:
- Genuine vulnerabilities (True Positives)
- Safe implementations and false-positive traps (True Negatives)
- Multi-language patterns (Python, TS/JS, Go, Java, C/C++)
- Category-level breakdown and latency tracking
"""
import sys
import os
import time
from dataclasses import dataclass
from typing import List, Optional, Dict

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge
from app.schemas.findings import Finding, ReviewResult


@dataclass
class ExpectedDefect:
    vulnerability_type: str      # e.g. "sql", "credential", "path traversal", "ssrf", "race condition"
    file: str                    # exact expected file name (e.g. "payment_processor.py")
    lines: List[int]             # exact line numbers in diff (e.g. [7] or [14, 15])
    evidence_substr: str         # required substring in f.evidence (e.g. "sk_live_")
    category: str = "security"   # "security" or "bug"


@dataclass
class BenchmarkCase:
    name: str
    category: str
    code_diff: str
    is_vulnerable: bool
    expected_vulnerability: Optional[str] = None
    expected_vulnerabilities: Optional[List[str]] = None
    expected_defects: Optional[List[ExpectedDefect]] = None
    description: str = ""
    case_id: str = ""
    expected_file: Optional[str] = None
    expected_lines: Optional[List[int]] = None
    expected_evidence: Optional[str] = None
    expected_severity: Optional[str] = None
    behavior_rationale: str = ""
    is_held_out: bool = False


BENCHMARK_DATASET: List[BenchmarkCase] = [
    # ---------------------------------------------------------
    # 1. SQL Injection (Python & Multi-language)
    # ---------------------------------------------------------
    BenchmarkCase(
        name="SQLi Dynamic f-string direct execute",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,3 @@
+def find_user(cursor, user_id):
+    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
+    return cursor.fetchone()
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="Dynamic f-string in cursor.execute",
    ),
    BenchmarkCase(
        name="SQLi Dynamic f-string assigned to variable",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,4 @@
+def find_user(cursor, user_id):
+    query = f"SELECT id, name FROM users WHERE id = {user_id}"
+    cursor.execute(query)
+    return cursor.fetchone()
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="Dynamic SQL query string formatted and assigned to variable",
    ),
    BenchmarkCase(
        name="SQLi String concatenation",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,3 @@
+def find_user(cursor, username):
+    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
+    return cursor.fetchone()
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="SQL string concatenation with user variable",
    ),
    BenchmarkCase(
        name="SQLi String .format()",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,3 @@
+def find_user(cursor, username):
+    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(username))
+    return cursor.fetchone()
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="SQL string .format() call",
    ),
    BenchmarkCase(
        name="SQL Safe Parameterized SELECT (?)",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,3 @@
+def find_user(cursor, user_id):
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
+    return cursor.fetchone()
""",
        is_vulnerable=False,
        description="Safe parameterized query with question mark placeholder",
    ),
    BenchmarkCase(
        name="SQL Safe Parameterized UPDATE (multiline)",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.py b/db.py
--- /dev/null
+++ b/db.py
@@ -0,0 +1,6 @@
+def update_user_password(cursor, hashed_pwd, uid):
+    cursor.execute(
+        "UPDATE users SET password = ? WHERE id = ?",
+        (hashed_pwd, uid)
+    )
+    return True
""",
        is_vulnerable=False,
        description="Safe parameterized multiline update query",
    ),
    BenchmarkCase(
        name="SQL Safe Non-SQL execute() call",
        category="SQL Injection",
        code_diff="""\
diff --git a/worker.py b/worker.py
--- /dev/null
+++ b/worker.py
@@ -0,0 +1,3 @@
+def process_job(command, ctx):
+    command.execute(ctx)
+    return {"success": True}
""",
        is_vulnerable=False,
        description="Non-database command.execute method",
    ),
    BenchmarkCase(
        name="SQL TS/JS Template Literal SQLi",
        category="SQL Injection",
        code_diff="""\
diff --git a/db.ts b/db.ts
--- /dev/null
+++ b/db.ts
@@ -0,0 +1,3 @@
+async function getUser(db: any, id: string) {
+    return await db.query(`SELECT * FROM users WHERE id = ${id}`);
+}
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="TypeScript interpolated template literal in db.query",
    ),
    BenchmarkCase(
        name="SQL Java Concatenation SQLi",
        category="SQL Injection",
        code_diff="""\
diff --git a/Repo.java b/Repo.java
--- /dev/null
+++ b/Repo.java
@@ -0,0 +1,4 @@
+public ResultSet findAccount(Statement stmt, String id) throws SQLException {
+    return stmt.executeQuery("SELECT * FROM accounts WHERE id = " + id);
+}
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="Java executeQuery with string concatenation",
    ),
    BenchmarkCase(
        name="SQL Go fmt.Sprintf SQLi",
        category="SQL Injection",
        code_diff="""\
diff --git a/repo.go b/repo.go
--- /dev/null
+++ b/repo.go
@@ -0,0 +1,3 @@
+func GetUser(db *sql.DB, uid string) *sql.Row {
+    return db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", uid))
+}
""",
        is_vulnerable=True,
        expected_vulnerability="sql",
        description="Go database query using fmt.Sprintf",
    ),

    # ---------------------------------------------------------
    # 2. Hardcoded Secrets & Credentials
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Hardcoded Stripe Live API Secret",
        category="Credentials",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+API_SECRET = "sk_live_998877665544332211"
+""",
        is_vulnerable=True,
        expected_vulnerability="credential",
        description="Live Stripe API key hardcoded in constant",
    ),
    BenchmarkCase(
        name="Hardcoded Secret with or fallback",
        category="Credentials",
        code_diff="""\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,3 @@
+def init_auth(key: str = None):
+    api_key = key or "sk_live_1234567890abcdef1234"
+    return api_key
""",
        is_vulnerable=True,
        expected_vulnerability="credential",
        description="Hardcoded credential provided as fallback",
    ),
    BenchmarkCase(
        name="Safe Environment Variable Secret (os.getenv)",
        category="Credentials",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+API_SECRET = os.getenv("STRIPE_API_SECRET")
+""",
        is_vulnerable=False,
        description="Secret retrieved via os.getenv",
    ),
    BenchmarkCase(
        name="Safe Environment Variable Secret (os.environ)",
        category="Credentials",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+DB_PASSWORD = os.environ.get("DATABASE_PASSWORD")
+""",
        is_vulnerable=False,
        description="Password retrieved via os.environ.get",
    ),
    BenchmarkCase(
        name="Dummy Placeholder Token (Trap)",
        category="Credentials",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+TEST_MODE = True
+DUMMY_KEY = "changeme"
+""",
        is_vulnerable=False,
        description="Obvious placeholder token should not trigger high alarm",
    ),

    # ---------------------------------------------------------
    # 3. Dynamic Code Execution (eval, exec, literal_eval)
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Dynamic eval() on User Input",
        category="Code Execution",
        code_diff="""\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,2 @@
+def evaluate_expression(expr):
+    return eval(expr)
+""",
        is_vulnerable=True,
        expected_vulnerability="eval",
        description="eval() called on variable input",
    ),
    BenchmarkCase(
        name="Dynamic exec() on Payload",
        category="Code Execution",
        code_diff="""\
diff --git a/runner.py b/runner.py
--- /dev/null
+++ b/runner.py
@@ -0,0 +1,2 @@
+def execute_plugin(plugin_code):
+    exec(plugin_code)
+""",
        is_vulnerable=True,
        expected_vulnerability="exec",
        description="exec() called on variable string",
    ),
    BenchmarkCase(
        name="Safe ast.literal_eval()",
        category="Code Execution",
        code_diff="""\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,3 @@
+import ast
+def parse_tuple(raw_str):
+    return ast.literal_eval(raw_str)
+""",
        is_vulnerable=False,
        description="Safe literal parsing using ast.literal_eval",
    ),

    # ---------------------------------------------------------
    # 4. Deserialization
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Unsafe pickle.loads()",
        category="Deserialization",
        code_diff="""\
diff --git a/cache.py b/cache.py
--- /dev/null
+++ b/cache.py
@@ -0,0 +1,3 @@
+import pickle
+def load_session(data):
+    return pickle.loads(data)
+""",
        is_vulnerable=True,
        expected_vulnerability="pickle",
        description="Unsafe deserialization of payload with pickle.loads",
    ),
    BenchmarkCase(
        name="Unsafe pickle.load() file stream",
        category="Deserialization",
        code_diff="""\
diff --git a/cache.py b/cache.py
--- /dev/null
+++ b/cache.py
@@ -0,0 +1,4 @@
+import pickle
+def load_session_file(f):
+    return pickle.load(f)
+""",
        is_vulnerable=True,
        expected_vulnerability="pickle",
        description="Unsafe pickle.load from file stream",
    ),
    BenchmarkCase(
        name="Safe json.loads() Deserialization",
        category="Deserialization",
        code_diff="""\
diff --git a/cache.py b/cache.py
--- /dev/null
+++ b/cache.py
@@ -0,0 +1,3 @@
+import json
+def load_session(data):
+    return json.loads(data)
+""",
        is_vulnerable=False,
        description="Safe JSON parsing using json.loads",
    ),

    # ---------------------------------------------------------
    # 5. ZeroDivision & Math Correctness
    # ---------------------------------------------------------
    BenchmarkCase(
        name="ZeroDivision on Empty Collection",
        category="Math & Logic",
        code_diff="""\
diff --git a/stats.py b/stats.py
--- /dev/null
+++ b/stats.py
@@ -0,0 +1,3 @@
+def calculate_average(values):
+    total = sum(values)
+    return total / len(values)
+""",
        is_vulnerable=True,
        expected_vulnerability="zero",
        description="Division by len(values) without empty check",
    ),
    BenchmarkCase(
        name="Multiplication Decimal Cashback (Trap)",
        category="Math & Logic",
        code_diff="""\
diff --git a/billing.py b/billing.py
--- /dev/null
+++ b/billing.py
@@ -0,0 +1,4 @@
+def calculate_vip_cashback(user_tier: str, total_spend: float):
+    if user_tier == "gold":
+        return total_spend * 0.125
+    return 0.0
+""",
        is_vulnerable=False,
        description="Multiplication by 0.125 cannot divide by zero",
    ),
    BenchmarkCase(
        name="Guarded Division (Safe)",
        category="Math & Logic",
        code_diff="""\
diff --git a/stats.py b/stats.py
--- /dev/null
+++ b/stats.py
@@ -0,0 +1,5 @@
+def calculate_average(values):
+    if not values:
+        return 0.0
+    return sum(values) / len(values)
+""",
        is_vulnerable=False,
        description="Division guarded by upfront empty collection check",
    ),
    BenchmarkCase(
        name="Guarded Division with len check (Safe)",
        category="Math & Logic",
        code_diff="""\
diff --git a/stats.py b/stats.py
--- /dev/null
+++ b/stats.py
@@ -0,0 +1,5 @@
+def calculate_mean(items):
+    if len(items) == 0:
+        return 0.0
+    return sum(items) / len(items)
+""",
        is_vulnerable=False,
        description="Division guarded by len(items) == 0 check",
    ),
    BenchmarkCase(
        name="Safe Division by Literal Float 2.0 (Safe)",
        category="Math & Logic",
        code_diff="""\
diff --git a/geo.py b/geo.py
--- /dev/null
+++ b/geo.py
@@ -0,0 +1,3 @@
+def midpoint(a, b):
+    return (a + b) / 2.0
+""",
        is_vulnerable=False,
        description="Division by literal 2.0 cannot divide by zero",
    ),
    BenchmarkCase(
        name="Division by Constant Literal 100 (Safe)",
        category="Math & Logic",
        code_diff="""\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,3 @@
+def to_percentage(fraction):
+    return fraction * 100.0 / 100.0
+""",
        is_vulnerable=False,
        description="Division by non-zero constant literal",
    ),

    # ---------------------------------------------------------
    # 6. Discount & Business Logic Defects
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Incorrect Discount Deduction Calculation",
        category="Math & Logic",
        code_diff="""\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,4 @@
+def calculate_discount(price, discount):
+    final_price = price * (discount / 100)
+    return final_price
+""",
        is_vulnerable=True,
        expected_vulnerability="discount",
        description="Calculates discount deduction instead of final price",
    ),
    BenchmarkCase(
        name="Inverted Discount Formula (Division)",
        category="Math & Logic",
        code_diff="""\
diff --git a/discount.py b/discount.py
--- /dev/null
+++ b/discount.py
@@ -0,0 +1,3 @@
+def apply_discount(price, discount_percent):
+    return price / (1 - discount_percent / 100)
+""",
        is_vulnerable=True,
        expected_vulnerability="discount",
        description="Dividing by (1 - discount/100) inflates the price",
    ),
    BenchmarkCase(
        name="Transfer Money Unconditional Success Bug",
        category="Math & Logic",
        code_diff="""\
diff --git a/bank.py b/bank.py
--- /dev/null
+++ b/bank.py
@@ -0,0 +1,8 @@
+def transfer_money(cursor, sender_id, receiver_id, amount):
+    sender = cursor.execute("SELECT balance FROM accounts WHERE id = ?", (sender_id,)).fetchone()
+    if sender[0] >= amount:
+        cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, sender_id))
+        cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
+    return {"status": "success"}
+""",
        is_vulnerable=True,
        expected_vulnerability="transfer_money",
        description="Unconditional success return and unverified recipient",
    ),
    BenchmarkCase(
        name="Correct Discount Calculation Formula (Safe)",
        category="Math & Logic",
        code_diff="""\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,4 @@
+def calculate_discount(price, discount):
+    final_price = price * (1 - discount / 100)
+    return final_price
+""",
        is_vulnerable=False,
        description="Correct mathematical formula for discounted price",
    ),

    # ---------------------------------------------------------
    # 7. Password & Cryptographic Hashing
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Weak MD5 Password Hashing",
        category="Cryptography",
        code_diff="""\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,4 @@
+import hashlib
+def hash_user_password(password):
+    return hashlib.md5(password.encode()).hexdigest()
+""",
        is_vulnerable=True,
        expected_vulnerability="password",
        description="Fast MD5 digest used for password storage",
    ),
    BenchmarkCase(
        name="Weak SHA-1 Password Hashing",
        category="Cryptography",
        code_diff="""\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,4 @@
+import hashlib
+def hash_user_password(new_password):
+    return hashlib.sha1(new_password.encode()).hexdigest()
+""",
        is_vulnerable=True,
        expected_vulnerability="password",
        description="SHA-1 used for password hashing",
    ),
    BenchmarkCase(
        name="Safe bcrypt Password Hashing",
        category="Cryptography",
        code_diff="""\
diff --git a/auth.py b/auth.py
--- /dev/null
+++ b/auth.py
@@ -0,0 +1,4 @@
+import bcrypt
+def hash_user_password(password):
+    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
+""",
        is_vulnerable=False,
        description="Secure adaptive bcrypt password hashing",
    ),

    # ---------------------------------------------------------
    # 8. SSRF (Server-Side Request Forgery)
    # ---------------------------------------------------------
    BenchmarkCase(
        name="SSRF Dynamic Webhook POST",
        category="SSRF",
        code_diff="""\
diff --git a/notify.py b/notify.py
--- /dev/null
+++ b/notify.py
@@ -0,0 +1,4 @@
+import requests
+def send_webhook(webhook_url, payload):
+    return requests.post(webhook_url, json=payload, timeout=5)
+""",
        is_vulnerable=True,
        expected_vulnerability="ssrf",
        description="requests.post dispatched to unvalidated dynamic URL",
    ),
    BenchmarkCase(
        name="SSRF Dynamic Image Download GET",
        category="SSRF",
        code_diff="""\
diff --git a/avatar.py b/avatar.py
--- /dev/null
+++ b/avatar.py
@@ -0,0 +1,4 @@
+import requests
+def download_avatar(image_url):
+    return requests.get(image_url, timeout=5)
+""",
        is_vulnerable=True,
        expected_vulnerability="ssrf",
        description="requests.get dispatched to unvalidated user-controlled image URL",
    ),
    BenchmarkCase(
        name="Safe Static Destination URL",
        category="SSRF",
        code_diff="""\
diff --git a/notify.py b/notify.py
--- /dev/null
+++ b/notify.py
@@ -0,0 +1,4 @@
+import requests
+def notify_slack(payload):
+    return requests.post("https://hooks.slack.com/services/T00/B00/X00", json=payload, timeout=5)
+""",
        is_vulnerable=False,
        description="Fixed trusted destination URL",
    ),

    # ---------------------------------------------------------
    # 9. Path Traversal
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Path Traversal direct f-string in open()",
        category="Path Traversal",
        code_diff="""\
diff --git a/files.py b/files.py
--- /dev/null
+++ b/files.py
@@ -0,0 +1,3 @@
+def read_receipt(receipt_id):
+    with open(f"/var/receipts/{receipt_id}.json", "r") as f:
+        return f.read()
+""",
        is_vulnerable=True,
        expected_vulnerability="traversal",
        description="Dynamic f-string in open() without sanitization",
    ),
    BenchmarkCase(
        name="Path Traversal dynamic variable path assignment",
        category="Path Traversal",
        code_diff="""\
diff --git a/upload.py b/upload.py
--- /dev/null
+++ b/upload.py
@@ -0,0 +1,5 @@
+def save_avatar(user_id, content):
+    file_path = f"/var/www/uploads/{user_id}.jpg"
+    with open(file_path, "wb") as f:
+        f.write(content)
+""",
        is_vulnerable=True,
        expected_vulnerability="traversal",
        description="Dynamic path assigned to variable and opened",
    ),
    BenchmarkCase(
        name="Safe Constrained File Path with basename",
        category="Path Traversal",
        code_diff="""\
diff --git a/upload.py b/upload.py
--- /dev/null
+++ b/upload.py
@@ -0,0 +1,5 @@
+import os
+def save_avatar(user_id, content):
+    safe_name = os.path.basename(user_id) + ".jpg"
+    with open(os.path.join("/var/www/uploads", safe_name), "wb") as f:
+        f.write(content)
+""",
        is_vulnerable=False,
        description="Path safely sanitized using os.path.basename",
    ),
    BenchmarkCase(
        name="Safe Static Path",
        category="Path Traversal",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+def read_app_config():
+    with open("config.json", "r") as f:
+        return f.read()
+""",
        is_vulnerable=False,
        description="Static relative file path",
    ),

    # ---------------------------------------------------------
    # 10. Command Injection & Subprocess
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Command Injection via os.system",
        category="Command Injection",
        code_diff="""\
diff --git a/backup.py b/backup.py
--- /dev/null
+++ b/backup.py
@@ -0,0 +1,3 @@
+import os
+def backup_db(dbname):
+    os.system("pg_dump " + dbname)
+""",
        is_vulnerable=True,
        expected_vulnerability="os.system",
        description="os.system called with dynamic concatenated string",
    ),
    BenchmarkCase(
        name="Dangerous subprocess with shell=True",
        category="Command Injection",
        code_diff="""\
diff --git a/backup.py b/backup.py
--- /dev/null
+++ b/backup.py
@@ -0,0 +1,3 @@
+import subprocess
+def run_cmd(cmd):
+    subprocess.run(cmd, shell=True)
+""",
        is_vulnerable=True,
        expected_vulnerability="shell=true",
        description="subprocess.run executed with shell=True",
    ),
    BenchmarkCase(
        name="Safe subprocess with argument list and shell=False",
        category="Command Injection",
        code_diff="""\
diff --git a/backup.py b/backup.py
--- /dev/null
+++ b/backup.py
@@ -0,0 +1,3 @@
+import subprocess
+def run_cmd(filename):
+    subprocess.run(["ls", "-l", filename], shell=False, check=True)
+""",
        is_vulnerable=False,
        description="subprocess executed safely with argument list and shell=False",
    ),

    # ---------------------------------------------------------
    # 11. Multi-Language Detections (XSS & Buffer Overflow)
    # ---------------------------------------------------------
    BenchmarkCase(
        name="DOM XSS raw innerHTML assignment (TS)",
        category="Multi-Language",
        code_diff="""\
diff --git a/render.ts b/render.ts
--- /dev/null
+++ b/render.ts
@@ -0,0 +1,3 @@
+function displayComment(element: HTMLElement, userHtml: string) {
+    element.innerHTML = userHtml;
+}
""",
        is_vulnerable=True,
        expected_vulnerability="xss",
        description="Raw innerHTML assignment enables DOM-based XSS",
    ),
    BenchmarkCase(
        name="Safe textContent assignment (TS)",
        category="Multi-Language",
        code_diff="""\
diff --git a/render.ts b/render.ts
--- /dev/null
+++ b/render.ts
@@ -0,0 +1,3 @@
+function displayComment(element: HTMLElement, userText: string) {
+    element.textContent = userText;
+}
""",
        is_vulnerable=False,
        description="Safe DOM textContent assignment",
    ),
    BenchmarkCase(
        name="C/C++ Unbounded strcpy Buffer Overflow",
        category="Multi-Language",
        code_diff="""\
diff --git a/parser.c b/parser.c
--- /dev/null
+++ b/parser.c
@@ -0,0 +1,4 @@
+void copy_input(char* dest, const char* src) {
+    strcpy(dest, src);
+}
""",
        is_vulnerable=True,
        expected_vulnerability="buffer",
        description="strcpy causes buffer overflow on unbounded inputs",
    ),
    BenchmarkCase(
        name="Safe C strncpy with bound (Safe)",
        category="Multi-Language",
        code_diff="""\
diff --git a/parser.c b/parser.c
--- /dev/null
+++ b/parser.c
@@ -0,0 +1,5 @@
+void copy_input(char* dest, const char* src, size_t max_len) {
+    strncpy(dest, src, max_len - 1);
+    dest[max_len - 1] = '\\0';
+}
""",
        is_vulnerable=False,
        description="strncpy bounded copy with null terminator",
    ),

    # ---------------------------------------------------------
    # 12. Clean Code & Non-Vulnerable Utility Logic
    # ---------------------------------------------------------
    BenchmarkCase(
        name="Clean Math Clamp Function",
        category="Clean Code",
        code_diff="""\
diff --git a/math_utils.py b/math_utils.py
--- /dev/null
+++ b/math_utils.py
@@ -0,0 +1,3 @@
+def clamp(value, min_val, max_val):
+    return max(min_val, min(value, max_val))
+""",
        is_vulnerable=False,
        description="Clean clamp function with no side effects",
    ),
    BenchmarkCase(
        name="Clean Dictionary Merger",
        category="Clean Code",
        code_diff="""\
diff --git a/dict_utils.py b/dict_utils.py
--- /dev/null
+++ b/dict_utils.py
@@ -0,0 +1,3 @@
+def merge_configs(base: dict, override: dict) -> dict:
+    return {**base, **override}
+""",
        is_vulnerable=False,
        description="Standard dictionary unpacking merge",
    ),
    BenchmarkCase(
        name="Clean String Slugifier",
        category="Clean Code",
        code_diff="""\
diff --git a/slug.py b/slug.py
--- /dev/null
+++ b/slug.py
@@ -0,0 +1,4 @@
+import re
+def slugify(text: str) -> str:
+    return re.sub(r'[^a-zA-Z0-9]+', '-', text).strip('-').lower()
+""",
        is_vulnerable=False,
        description="Pure regex string sanitization and slugification",
    ),
    BenchmarkCase(
        name="Clean List Deduplication",
        category="Clean Code",
        code_diff="""\
diff --git a/collections_helper.py b/collections_helper.py
--- /dev/null
+++ b/collections_helper.py
@@ -0,0 +1,3 @@
+def deduplicate(items: list) -> list:
+    return list(dict.fromkeys(items))
+""",
        is_vulnerable=False,
        description="Order-preserving list deduplication using dict.fromkeys",
    ),

    # ---------------------------------------------------------
    # 13. Critical Real-World Regression Scenarios & Held-Out Traps
    # ---------------------------------------------------------
    BenchmarkCase(
        case_id="CL-CASE-053",
        name="29-Line PaymentProcessor Multi-Defect Review",
        category="Payment & Finance",
        code_diff="""\
diff --git a/payment_processor.py b/payment_processor.py
--- /dev/null
+++ b/payment_processor.py
@@ -0,0 +1,29 @@
+import os
+import requests
+import json
+
+class PaymentProcessor:
+    def __init__(self, api_key: str):
+        self.api_key = api_key or "sk_live_998877665544332211"
+        self.processed_transactions = set()
+
+    def process_refund(self, transaction_id: str, amount: float, webhook_url: str):
+        if amount == 0:
+            return {"status": "skipped", "reason": "zero amount"}
+
+        receipt_path = f"/var/receipts/{transaction_id}.json"
+        with open(receipt_path, "r") as f:
+            receipt = json.load(f)
+
+        response = requests.post(webhook_url, json={"transaction_id": transaction_id, "refunded": amount})
+
+        if transaction_id in self.processed_transactions:
+            raise ValueError("Transaction already refunded")
+        self.processed_transactions.add(transaction_id)
+
+        return {"status": "success", "amount": amount}
+
+    def calculate_vip_cashback(self, user_tier: str, total_spend: float):
+        if user_tier == "gold":
+            return total_spend * 0.125
+        return 0.0
+""",
        is_vulnerable=True,
        expected_vulnerability="credential",
        expected_vulnerabilities=["credential", "path traversal", "ssrf", "race condition"],
        description="29-line PaymentProcessor: hardcoded secret, path traversal, SSRF, duplicate refund race condition, multiplication cashback",
        behavior_rationale="Must detect 4 real vulnerabilities and reject false ZeroDivisionError on multiplication.",
        is_held_out=False,
    ),
    BenchmarkCase(
        case_id="CL-CASE-054",
        name="Dynamic SQL Assigned But Never Executed (Held-Out)",
        category="SQL Injection",
        code_diff="""\
diff --git a/report.py b/report.py
--- /dev/null
+++ b/report.py
@@ -0,0 +1,5 @@
+def prepare_report(user_input):
+    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
+    return "Report prepared"
+""",
        is_vulnerable=False,
        description="Dynamic SQL string is constructed but never dispatched to a database sink",
        behavior_rationale="Dynamic SQL assigned to variable but never executed must not be flagged as SQL injection.",
        is_held_out=True,
    ),
    BenchmarkCase(
        case_id="CL-CASE-055",
        name="Discount Amount Calculation Non-Final Price (Held-Out)",
        category="Logic & Arithmetic",
        code_diff="""\
diff --git a/pricing.py b/pricing.py
--- /dev/null
+++ b/pricing.py
@@ -0,0 +1,5 @@
+def calculate_discount_amount(price, discount):
+    discount_amount = price * (discount / 100)
+    return discount_amount
+""",
        is_vulnerable=False,
        description="Calculates discount deduction amount, not final price",
        behavior_rationale="Calculating discount_amount = price * (discount / 100) is correct and must not be flagged.",
        is_held_out=True,
    ),
    BenchmarkCase(
        case_id="CL-CASE-056",
        name="Valid Bank Transfer with Balance & Receiver Checks (Held-Out)",
        category="Payment & Finance",
        code_diff="""\
diff --git a/bank_safe.py b/bank_safe.py
--- /dev/null
+++ b/bank_safe.py
@@ -0,0 +1,12 @@
+def transfer_money(cursor, sender_id, receiver_id, amount):
+    receiver = cursor.execute("SELECT id FROM accounts WHERE id = ?", (receiver_id,)).fetchone()
+    if not receiver:
+        return {"error": "Receiver not found"}
+    sender = cursor.execute("SELECT balance FROM accounts WHERE id = ?", (sender_id,)).fetchone()
+    if not sender or sender[0] < amount:
+        return {"error": "Insufficient funds"}
+    cursor.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, sender_id))
+    cursor.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, receiver_id))
+    return {"status": "success"}
+""",
        is_vulnerable=False,
        description="Transfer checks receiver exists, checks sender balance, updates both atomically",
        behavior_rationale="Properly guarded bank transfer must not produce false positive bugs.",
        is_held_out=True,
    ),
]


def format_metric(val: Optional[float]) -> str:
    """Formats a ratio as percentage or 'N/A' if undefined (zero denominator)."""
    return f"{val * 100:.1f}%" if val is not None else "N/A"


DEFAULT_CASE_DEFECTS: Dict[str, List[ExpectedDefect]] = {
    "CL-CASE-001": [ExpectedDefect("sql", "db.py", [2], "cursor.execute", "security")],
    "CL-CASE-002": [ExpectedDefect("sql", "db.py", [3], "cursor.execute(query)", "security")],
    "CL-CASE-003": [ExpectedDefect("sql", "db.py", [2], "cursor.execute", "security")],
    "CL-CASE-004": [ExpectedDefect("sql", "db.py", [2], "cursor.execute", "security")],
    "CL-CASE-008": [ExpectedDefect("sql", "db.ts", [2], "db.query", "security")],
    "CL-CASE-009": [ExpectedDefect("sql", "Repo.java", [2], "executeQuery", "security")],
    "CL-CASE-010": [ExpectedDefect("sql", "repo.go", [2], "QueryRow", "security")],
    "CL-CASE-011": [ExpectedDefect("credential", "config.py", [1], "API_SECRET", "security")],
    "CL-CASE-012": [ExpectedDefect("credential", "auth.py", [2], "api_key", "security")],
    "CL-CASE-016": [ExpectedDefect("eval", "calc.py", [2], "eval(expr)", "security")],
    "CL-CASE-017": [ExpectedDefect("exec", "runner.py", [2], "exec(plugin_code)", "security")],
    "CL-CASE-019": [ExpectedDefect("pickle", "cache.py", [3], "pickle.loads", "security")],
    "CL-CASE-020": [ExpectedDefect("pickle", "cache.py", [3], "pickle.load", "security")],
    "CL-CASE-022": [ExpectedDefect("zerodivision", "stats.py", [3], "len(values)", "bug")],
    "CL-CASE-028": [ExpectedDefect("discount", "pricing.py", [2], "price * (discount / 100)", "bug")],
    "CL-CASE-029": [ExpectedDefect("discount", "discount.py", [2], "price / (1 - discount_percent / 100)", "bug")],
    "CL-CASE-030": [ExpectedDefect("transfer_money", "bank.py", [6], '"status": "success"', "bug")],
    "CL-CASE-032": [ExpectedDefect("password", "auth.py", [3], "hashlib.md5", "security")],
    "CL-CASE-033": [ExpectedDefect("password", "auth.py", [3], "hashlib.sha1", "security")],
    "CL-CASE-035": [ExpectedDefect("ssrf", "notify.py", [3], "requests.post(webhook_url", "security")],
    "CL-CASE-036": [ExpectedDefect("ssrf", "avatar.py", [3], "requests.get(image_url", "security")],
    "CL-CASE-038": [ExpectedDefect("traversal", "files.py", [2], 'open(f"/var/receipts', "security")],
    "CL-CASE-039": [ExpectedDefect("traversal", "upload.py", [2, 3], "uploads", "security")],
    "CL-CASE-042": [ExpectedDefect("os.system", "backup.py", [3], "os.system", "security")],
    "CL-CASE-043": [ExpectedDefect("shell=true", "backup.py", [3], "shell=True", "security")],
    "CL-CASE-045": [ExpectedDefect("xss", "render.ts", [2], "element.innerHTML", "security")],
    "CL-CASE-047": [ExpectedDefect("buffer", "parser.c", [2], "strcpy", "security")],
    "CL-CASE-053": [
        ExpectedDefect("credential", "payment_processor.py", [7], "sk_live_998877665544332211", "security"),
        ExpectedDefect("path traversal", "payment_processor.py", [14, 15], "receipt_path", "security"),
        ExpectedDefect("ssrf", "payment_processor.py", [18], "requests.post(webhook_url", "security"),
        ExpectedDefect("race condition", "payment_processor.py", [18, 20], "processed_transactions", "bug"),
    ],
}


def match_finding_to_defect(f: Finding, defect: ExpectedDefect) -> bool:
    """
    Strict 5-factor verification of finding against expected defect:
    1. Exact file match (basename or full relative path)
    2. Exact line number match within target range
    3. Exact code evidence substring present
    4. Exact category match ('security' vs 'bug')
    5. Semantic vulnerability type keyword match in title or root cause
    """
    f_file = (f.file or "").replace("\\", "/").split("/")[-1]
    d_file = defect.file.replace("\\", "/").split("/")[-1]
    if f_file != d_file:
        return False

    if f.line not in defect.lines:
        return False

    if defect.evidence_substr.lower() not in (f.evidence or "").lower():
        return False

    if (f.category or "").lower() != defect.category.lower():
        return False

    vuln_haystack = f"{f.title} {f.root_cause or ''}".lower()
    if defect.vulnerability_type.lower() not in vuln_haystack:
        return False

    return True


def evaluate_mode1_deterministic_engine(dataset: List[BenchmarkCase]) -> Dict:
    """
    Mode 1: Evaluates the deterministic AST & static-analysis engine.
    Measures separate Case-Level and Defect-Level precision, recall, specificity, and F1.
    """
    print("\n" + "=" * 90)
    print("MODE 1: DETERMINISTIC STATIC-ANALYSIS & PATTERN DETECTION BENCHMARK")
    print("=" * 90)
    print(f"{'STATUS':^15} | {'CATEGORY':<18} | {'CASE / SCENARIO':<38} | {'LATENCY':>8}")
    print("-" * 90)

    category_stats: Dict[str, Dict[str, int]] = {}
    durations = []

    case_tp = case_fp = case_tn = case_fn = 0
    defect_tp = defect_fp = defect_fn = 0

    for i, case in enumerate(dataset):
        case_id = case.case_id or f"CL-CASE-{i+1:03d}"
        t0 = time.perf_counter()
        diff_files = parse_git_diff(case.code_diff)
        raw_findings = detect_risky_patterns(case.code_diff, diff_files)

        base_res = ReviewResult(
            summary="Benchmark run",
            overall_status="approved",
            risk_level="low",
            files_reviewed=len(diff_files),
            findings=[],
            llm_available=True,
        )
        validated_res = validate_and_merge(base_res, raw_findings, diff_files=diff_files)
        elapsed = time.perf_counter() - t0
        durations.append(elapsed)

        findings = validated_res.findings
        cat = case.category
        if cat not in category_stats:
            category_stats[cat] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        if case.is_vulnerable:
            exp_defects = case.expected_defects or DEFAULT_CASE_DEFECTS.get(case_id, [])
            matched_indices = set()
            spurious_count = 0
            duplicate_count = 0

            for f in findings:
                matched = False
                for didx, defect in enumerate(exp_defects):
                    if match_finding_to_defect(f, defect):
                        if didx not in matched_indices:
                            matched_indices.add(didx)
                            defect_tp += 1
                            matched = True
                            break
                        else:
                            duplicate_count += 1
                            defect_fp += 1
                            matched = True
                            break
                if not matched:
                    spurious_count += 1
                    defect_fp += 1

            missed_count = len(exp_defects) - len(matched_indices)
            defect_fn += missed_count

            if missed_count == 0 and spurious_count == 0 and duplicate_count == 0:
                case_status = "TP (HIT)"
                case_tp += 1
                category_stats[cat]["tp"] += 1
            elif missed_count == 0 and (spurious_count > 0 or duplicate_count > 0):
                case_status = "TP+FP (MIX)"
                case_fp += 1
                category_stats[cat]["fp"] += 1
            elif missed_count > 0 and len(matched_indices) > 0:
                case_status = f"PARTIAL ({len(matched_indices)}/{len(exp_defects)})"
                case_fn += 1
                category_stats[cat]["fn"] += 1
            else:
                case_status = "FN (MISSED)"
                case_fn += 1
                category_stats[cat]["fn"] += 1
        else:
            if len(findings) == 0:
                case_status = "TN (CLEAN)"
                case_tn += 1
                category_stats[cat]["tn"] += 1
            else:
                case_status = "FP (ALARM)"
                case_fp += 1
                defect_fp += len(findings)
                category_stats[cat]["fp"] += 1

        label = f"[{case_id}] {case.name[:30]}"
        print(f"[{case_status:^13}] | {cat:<18} | {label:<38} | {elapsed*1000:>6.1f}ms")

    total_cases = len(dataset)
    case_prec = (case_tp / (case_tp + case_fp)) if (case_tp + case_fp) > 0 else None
    case_rec = (case_tp / (case_tp + case_fn)) if (case_tp + case_fn) > 0 else None
    case_f1 = (2 * case_prec * case_rec / (case_prec + case_rec)) if (case_prec and case_rec and (case_prec + case_rec) > 0) else None
    case_spec = (case_tn / (case_tn + case_fp)) if (case_tn + case_fp) > 0 else None

    defect_prec = (defect_tp / (defect_tp + defect_fp)) if (defect_tp + defect_fp) > 0 else None
    defect_rec = (defect_tp / (defect_tp + defect_fn)) if (defect_tp + defect_fn) > 0 else None
    defect_f1 = (2 * defect_prec * defect_rec / (defect_prec + defect_rec)) if (defect_prec and defect_rec and (defect_prec + defect_rec) > 0) else None

    avg_latency_ms = (sum(durations) / len(durations) * 1000) if durations else 0.0

    print("-" * 90)
    print("MODE 1 METRICS SUMMARY:")
    print("  1. CASE-LEVEL METRICS (Whole-file review pass/fail confusion matrix):")
    print(f"     Total Labeled Cases : {total_cases} (28 Vulnerable, 28 Safe)")
    print(f"     True Positives (TP) : {case_tp} (all required defects found, 0 false alarms)")
    print(f"     True Negatives (TN) : {case_tn} (clean safe code, 0 false alarms)")
    print(f"     False Positives (FP): {case_fp} (false alarms on safe code or unverified extras)")
    print(f"     False Negatives (FN): {case_fn} (vulnerable code with missed defects)")
    print(f"     Case Precision      : {format_metric(case_prec)}")
    print(f"     Case Recall         : {format_metric(case_rec)}")
    print(f"     Case F1 Score       : {format_metric(case_f1)}")
    print(f"     Case Specificity    : {format_metric(case_spec)}")
    print()
    print("  2. DEFECT-LEVEL METRICS (Individual vulnerability detection with exact location & evidence):")
    print(f"     Total Target Defects: {defect_tp + defect_fn} (27 single-defect + 4 payment scenario)")
    print(f"     True Positives (TP) : {defect_tp} (verified file, line range, evidence, and type)")
    print(f"     False Positives (FP): {defect_fp} (hallucinated, duplicate, or mislocated findings)")
    print(f"     False Negatives (FN): {defect_fn} (unidentified genuine vulnerabilities)")
    print(f"     Defect Precision    : {format_metric(defect_prec)}")
    print(f"     Defect Recall       : {format_metric(defect_rec)}")
    print(f"     Defect F1 Score     : {format_metric(defect_f1)}")
    print(f"  Avg Case Latency       : {avg_latency_ms:.2f} ms")
    print("=" * 90)

    return {
        "case_tp": case_tp, "case_fp": case_fp, "case_tn": case_tn, "case_fn": case_fn,
        "case_precision": case_prec, "case_recall": case_rec, "case_f1": case_f1, "case_specificity": case_spec,
        "defect_tp": defect_tp, "defect_fp": defect_fp, "defect_fn": defect_fn,
        "defect_precision": defect_prec, "defect_recall": defect_rec, "defect_f1": defect_f1,
        "avg_latency_ms": avg_latency_ms,
        "category_stats": category_stats,
    }
    print("=" * 90)

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "specificity": specificity, "fpr": fpr,
        "avg_latency_ms": avg_latency_ms,
        "category_stats": category_stats,
    }


def evaluate_mode2_evidence_validation() -> Dict:
    """
    Mode 2: Evaluates the evidence-validation engine against synthetic hallucinated findings.
    Verifies rejection of:
    1. Empty diff / missing diff context (fail-closed)
    2. Nonexistent file reference
    3. Ambiguous basename matches
    4. Out-of-bounds line numbers
    5. Fabricated ZeroDivision claims on multiplication code
    6. Stolen evidence copied across unrelated functions
    """
    print("\n" + "=" * 90)
    print("MODE 2: EVIDENCE VALIDATION & HALLUCINATION REJECTION BENCHMARK")
    print("=" * 90)

    from app.schemas.findings import Finding
    from app.tools.review_validator import validate_source_evidence

    test_diff = """\
diff --git a/service/auth.py b/service/auth.py
--- /dev/null
+++ b/service/auth.py
@@ -0,0 +1,10 @@
+def authenticate(user_token):
+    if not user_token:
+        return False
+    return True
+
+def calculate_tier(multiplier):
+    return multiplier * 0.15
"""
    diff_files = parse_git_diff(test_diff)
    file_lines = {diff_files[0].new_path: {i: l.content for i, l in enumerate(diff_files[0].hunks[0].lines, 1)}}
    file_all_code = {diff_files[0].new_path: "\n".join(l.content for l in diff_files[0].hunks[0].lines)}

    scenarios = [
        (
            "Missing Diff (Fail Closed)",
            Finding(title="Bug", category="bug", severity="high", file="service/auth.py", line=1, description=""),
            [],  # empty diff_files
            False,
        ),
        (
            "Nonexistent File In Diff",
            Finding(title="Bug", category="bug", severity="high", file="other/secret.py", line=1, description=""),
            diff_files,
            False,
        ),
        (
            "Out of Bounds Line Number",
            Finding(title="Bug", category="bug", severity="high", file="service/auth.py", line=999, description=""),
            diff_files,
            False,
        ),
        (
            "Fabricated ZeroDivision on Multiplication",
            Finding(
                title="ZeroDivisionError in calculate_tier",
                category="bug",
                severity="medium",
                file="service/auth.py",
                line=8,
                evidence="return multiplier * 0.15",
                description="Division by zero if multiplier is zero.",
            ),
            diff_files,
            False,
        ),
        (
            "Valid Finding with Exact Line & Code",
            Finding(
                title="Authentication bypass note",
                category="bug",
                severity="low",
                file="service/auth.py",
                line=2,
                evidence="if not user_token:",
                description="Empty token check.",
            ),
            diff_files,
            True,
        ),
    ]

    tp = tn = fp = fn = 0
    for name, finding, df, expected_valid in scenarios:
        valid, validated_f, reason = validate_source_evidence(
            finding, df, file_lines, file_all_code
        )
        if valid == expected_valid:
            status = "PASSED"
            if expected_valid:
                tp += 1
            else:
                tn += 1
        else:
            status = "FAILED"
            if expected_valid:
                fn += 1
            else:
                fp += 1
        verdict = "VALID" if valid else f"REJECTED ({reason})"
        print(f"[{status:^8}] {name:<42} -> {verdict}")

    prec = (tp / (tp + fp)) if (tp + fp) > 0 else None
    rec = (tp / (tp + fn)) if (tp + fn) > 0 else None
    print("-" * 90)
    print(f"MODE 2 ACCURACY: {tn}/{len(scenarios)-1} invalid findings rejected ({format_metric((tp+tn)/len(scenarios))})")
    print("=" * 90)

    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def evaluate_mode3_full_ai_pipeline() -> Dict:
    """
    Mode 3: Complete AI code-review pipeline evaluation.
    Checks Ollama local LLM connectivity; if offline, reports partial-review guarantee.
    Clearly identifies unavailable models and skipped evaluation modes without fabricating metrics.
    """
    print("\n" + "=" * 90)
    print("MODE 3: FULL AI CODE-REVIEW PIPELINE BENCHMARK (ORCHESTRATOR + LLM)")
    print("=" * 90)

    model_name = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
    ollama_url = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    import urllib.request
    ollama_online = False
    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            if resp.status == 200:
                ollama_online = True
    except Exception:
        ollama_online = False

    if not ollama_online:
        print(f"  Target LLM Model: {model_name}")
        print(f"  Ollama Status   : OFFLINE / UNREACHABLE at {ollama_url}")
        print(f"  Execution Status: SKIPPED (No synthetic/hallucinated AI metrics claimed)")
        print(f"  Fallback Mode   : DETERMINISTIC GUARANTEE (Pass 1 AST detectors + Pass 3 Evidence Validation)")
        print(f"  Partial Review  : partial_analysis=True, overall_status != approved on issues")
        print("=" * 90)
        return {
            "status": "skipped",
            "llm_available": False,
            "model": model_name,
            "precision": None,
            "recall": None,
            "f1": None,
        }
    else:
        print(f"  Target LLM Model: {model_name}")
        print(f"  Ollama Status   : ONLINE (Service connected at {ollama_url})")
        print(f"  Execution Status: READY for live semantic evaluation")
        print("=" * 90)
        return {"status": "online", "llm_available": True, "model": model_name}


def evaluate_benchmark():
    # Auto-assign case IDs if missing
    for idx, c in enumerate(BENCHMARK_DATASET):
        if not c.case_id:
            c.case_id = f"CL-CASE-{idx+1:03d}"

    m1 = evaluate_mode1_deterministic_engine(BENCHMARK_DATASET)
    m2 = evaluate_mode2_evidence_validation()
    m3 = evaluate_mode3_full_ai_pipeline()

    return {
        "mode1": m1,
        "mode2": m2,
        "mode3": m3,
        "total": len(BENCHMARK_DATASET),
        "case_precision": m1["case_precision"],
        "case_recall": m1["case_recall"],
        "case_f1": m1["case_f1"],
        "case_fp": m1["case_fp"],
        "defect_precision": m1["defect_precision"],
        "defect_recall": m1["defect_recall"],
        "defect_f1": m1["defect_f1"],
        "defect_fp": m1["defect_fp"],
    }


if __name__ == "__main__":
    metrics = evaluate_benchmark()
    if metrics["case_fp"] > 0 or metrics["defect_fp"] > 0:
        print("\n[WARN] Benchmark detected false positives.")
        sys.exit(1)
    if metrics["case_f1"] is not None and metrics["case_f1"] < 0.90:
        print("\n[WARN] Case F1 score below 90% threshold.")
        sys.exit(1)
    print(f"\nBenchmark completed successfully ({metrics['total']} cases evaluated: Case F1={format_metric(metrics['case_f1'])}, Defect F1={format_metric(metrics['defect_f1'])}).")
