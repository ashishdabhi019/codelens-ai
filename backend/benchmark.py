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
from app.schemas.findings import ReviewResult


@dataclass
class BenchmarkCase:
    name: str
    category: str
    code_diff: str
    is_vulnerable: bool
    expected_vulnerability: Optional[str] = None
    description: str = ""


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
]


def evaluate_benchmark():
    category_stats: Dict[str, Dict[str, int]] = {}
    durations = []
    tp_total = 0
    fp_total = 0
    tn_total = 0
    fn_total = 0

    print("=" * 86)
    print("CODELENS AI — 52-CASE PRECISION, RECALL & F1 BENCHMARK SUITE")
    print("=" * 86)
    print(f"{'STATUS':^15} | {'CATEGORY':<18} | {'BENCHMARK CASE':<36} | {'LATENCY':>8}")
    print("-" * 86)

    for case in BENCHMARK_DATASET:
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
        has_finding = len(findings) > 0

        cat = case.category
        if cat not in category_stats:
            category_stats[cat] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

        matched = False
        if has_finding and case.is_vulnerable:
            if case.expected_vulnerability:
                matched = any(
                    case.expected_vulnerability in (f.title + " " + (f.root_cause or "")).lower()
                    for f in findings
                )
            else:
                matched = True

        if case.is_vulnerable:
            if has_finding and matched:
                status = "TP (HIT)"
                tp_total += 1
                category_stats[cat]["tp"] += 1
            else:
                status = "FN (MISSED)"
                fn_total += 1
                category_stats[cat]["fn"] += 1
        else:
            if not has_finding:
                status = "TN (CLEAN)"
                tn_total += 1
                category_stats[cat]["tn"] += 1
            else:
                status = "FP (FALSE ALARM)"
                fp_total += 1
                category_stats[cat]["fp"] += 1

        print(f"[{status:^13}] | {cat:<18} | {case.name[:36]:<36} | {elapsed*1000:>6.1f}ms")

    # Overall Metrics Calculation
    total = len(BENCHMARK_DATASET)
    precision = (tp_total / (tp_total + fp_total)) if (tp_total + fp_total) > 0 else 1.0
    recall = (tp_total / (tp_total + fn_total)) if (tp_total + fn_total) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp_total / (fp_total + tn_total)) if (fp_total + tn_total) > 0 else 0.0
    avg_latency_ms = (sum(durations) / len(durations)) * 1000

    print("=" * 86)
    print("CATEGORY BREAKDOWN:")
    print("-" * 86)
    print(f"{'CATEGORY':<20} | {'TP':>4} | {'FP':>4} | {'TN':>4} | {'FN':>4} | {'PRECISION':>10} | {'RECALL':>8} | {'F1':>8}")
    print("-" * 86)
    for cat, stats in sorted(category_stats.items()):
        c_tp = stats["tp"]
        c_fp = stats["fp"]
        c_tn = stats["tn"]
        c_fn = stats["fn"]
        c_prec = (c_tp / (c_tp + c_fp)) if (c_tp + c_fp) > 0 else (1.0 if c_fn == 0 else 0.0)
        c_rec = (c_tp / (c_tp + c_fn)) if (c_tp + c_fn) > 0 else 1.0
        c_f1 = (2 * c_prec * c_rec / (c_prec + c_rec)) if (c_prec + c_rec) > 0 else 0.0
        print(f"{cat:<20} | {c_tp:>4} | {c_fp:>4} | {c_tn:>4} | {c_fn:>4} | {c_prec*100:>9.1f}% | {c_rec*100:>7.1f}% | {c_f1*100:>7.1f}%")

    print("-" * 86)
    print("OVERALL METRICS SUMMARY:")
    print(f"  Total Labeled Cases : {total}")
    print(f"  True Positives (TP) : {tp_total}")
    print(f"  True Negatives (TN) : {tn_total}")
    print(f"  False Positives (FP): {fp_total}")
    print(f"  False Negatives (FN): {fn_total}")
    print(f"  Precision           : {precision * 100:.1f}%")
    print(f"  Recall              : {recall * 100:.1f}%")
    print(f"  F1 Score            : {f1 * 100:.1f}%")
    print(f"  False Positive Rate : {fpr * 100:.1f}%")
    print(f"  Avg Case Latency    : {avg_latency_ms:.2f} ms")
    print("=" * 86)

    return {
        "total": total,
        "tp": tp_total,
        "fp": fp_total,
        "tn": tn_total,
        "fn": fn_total,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "avg_latency_ms": avg_latency_ms,
        "category_stats": category_stats,
    }


if __name__ == "__main__":
    metrics = evaluate_benchmark()
    if metrics["fp"] > 0:
        print("\n[WARN] Benchmark detected false positives.")
        sys.exit(1)
    if metrics["f1"] < 0.90:
        print("\n[WARN] F1 score below 90% threshold.")
        sys.exit(1)
    print(f"\nBenchmark completed successfully ({metrics['total']} cases, {metrics['precision']*100:.1f}% precision, {metrics['recall']*100:.1f}% recall, {metrics['f1']*100:.1f}% F1).")
