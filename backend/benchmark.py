#!/usr/bin/env python3
"""
CodeLens AI — Automated Precision, Recall, and F1 Benchmark Suite.

Evaluates deterministic static analysis, finding validation, and end-to-end review accuracy
across true positives, false-positive traps, true negatives, and subtle logic defects.
"""
import sys
import os
import time
import asyncio
from dataclasses import dataclass
from typing import List, Optional

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge
from app.schemas.findings import ReviewResult, Finding


@dataclass
class BenchmarkCase:
    name: str
    category: str
    code_diff: str
    is_vulnerable: bool
    expected_vulnerability: Optional[str] = None
    description: str = ""


BENCHMARK_DATASET: List[BenchmarkCase] = [
    # 1. SQL Injection: Vulnerable f-string (True Positive)
    BenchmarkCase(
        name="SQLi Dynamic f-string",
        category="Security",
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
        description="Dynamic f-string in SQL query",
    ),

    # 2. SQL Injection: Parameterized Query (False-Positive Trap / True Negative)
    BenchmarkCase(
        name="SQL Parameterized Query (Safe)",
        category="Security",
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
        description="Safe parameterized query with tuple parameter placeholder",
    ),

    # 3. Hardcoded Secret (True Positive)
    BenchmarkCase(
        name="Hardcoded API Secret",
        category="Security",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,2 @@
+def init_stripe():
+    api_key = "sk_live_998877665544332211"
""",
        is_vulnerable=True,
        expected_vulnerability="credential",
        description="Production live Stripe API secret key hardcoded in source",
    ),

    # 4. Safe Environment Secret (False-Positive Trap / True Negative)
    BenchmarkCase(
        name="Safe Environment Variable Secret",
        category="Security",
        code_diff="""\
diff --git a/config.py b/config.py
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+def init_stripe():
+    api_key = os.getenv("STRIPE_API_KEY")
""",
        is_vulnerable=False,
        description="API key safely retrieved from environment variables",
    ),

    # 5. Arbitrary eval() on variable (True Positive)
    BenchmarkCase(
        name="Dynamic eval() on User Input",
        category="Security",
        code_diff="""\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,2 @@
+def evaluate_expression(expr):
+    return eval(expr)
""",
        is_vulnerable=True,
        expected_vulnerability="eval",
        description="Dangerous eval() called with variable argument",
    ),

    # 6. ast.literal_eval (False-Positive Trap / True Negative)
    BenchmarkCase(
        name="Safe ast.literal_eval()",
        category="Security",
        code_diff="""\
diff --git a/calc.py b/calc.py
--- /dev/null
+++ b/calc.py
@@ -0,0 +1,3 @@
+import ast
+def parse_tuple(raw_str):
+    return ast.literal_eval(raw_str)
""",
        is_vulnerable=False,
        description="ast.literal_eval safely parses python literals without executing code",
    ),

    # 7. Unsafe pickle.loads (True Positive)
    BenchmarkCase(
        name="Unsafe pickle.loads() Deserialization",
        category="Security",
        code_diff="""\
diff --git a/cache.py b/cache.py
--- /dev/null
+++ b/cache.py
@@ -0,0 +1,3 @@
+import pickle
+def load_session(data):
+    return pickle.loads(data)
""",
        is_vulnerable=True,
        expected_vulnerability="pickle",
        description="pickle.loads on untrusted payload allows RCE",
    ),

    # 8. ZeroDivision on empty collection (True Positive)
    BenchmarkCase(
        name="ZeroDivision on Empty Collection",
        category="Logic",
        code_diff="""\
diff --git a/stats.py b/stats.py
--- /dev/null
+++ b/stats.py
@@ -0,0 +1,3 @@
+def calculate_average(values):
+    total = sum(values)
+    return total / len(values)
""",
        is_vulnerable=True,
        expected_vulnerability="zero",
        description="Division by len(values) without empty check",
    ),

    # 9. Multiplication Decimal Calculation (False-Positive Trap / True Negative)
    BenchmarkCase(
        name="Multiplication Decimal Cashback (Trap)",
        category="Logic",
        code_diff="""\
diff --git a/billing.py b/billing.py
--- /dev/null
+++ b/billing.py
@@ -0,0 +1,4 @@
+def calculate_vip_cashback(user_tier: str, total_spend: float):
+    if user_tier == "gold":
+        return total_spend * 0.125
+    return 0.0
""",
        is_vulnerable=False,
        description="Multiplication by 0.125 cannot trigger ZeroDivisionError",
    ),

    # 10. Inverted Discount Formula (True Positive)
    BenchmarkCase(
        name="Inverted Discount Formula",
        category="Logic",
        code_diff="""\
diff --git a/discount.py b/discount.py
--- /dev/null
+++ b/discount.py
@@ -0,0 +1,3 @@
+def apply_discount(price, discount_percent):
+    return price / (1 - discount_percent / 100)
""",
        is_vulnerable=True,
        expected_vulnerability="discount",
        description="Dividing by discount factor inflates price instead of discounting",
    ),

    # 11. Clean Production Code (True Negative)
    BenchmarkCase(
        name="Clean Math Function",
        category="Clean Code",
        code_diff="""\
diff --git a/math_utils.py b/math_utils.py
--- /dev/null
+++ b/math_utils.py
@@ -0,0 +1,3 @@
+def clamp(value, min_val, max_val):
+    return max(min_val, min(value, max_val))
""",
        is_vulnerable=False,
        description="Simple clean clamp function with no side effects or vulnerabilities",
    ),

    # 12. Path Traversal via dynamic file path (True Positive)
    BenchmarkCase(
        name="Path Traversal in open()",
        category="Security",
        code_diff="""\
diff --git a/files.py b/files.py
--- /dev/null
+++ b/files.py
@@ -0,0 +1,3 @@
+def read_receipt(receipt_id):
+    with open(f"/var/receipts/{receipt_id}.json", "r") as f:
+        return f.read()
""",
        is_vulnerable=True,
        expected_vulnerability="traversal",
        description="Dynamic f-string in file path without sanitization",
    ),
]


def evaluate_deterministic_benchmark():
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    durations = []

    print("=" * 80)
    print("CODELENS AI — DETERMINISTIC & FINDING-VALIDATION BENCHMARK")
    print("=" * 80)

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

        # Check if finding matched expected vulnerability
        matched = False
        if has_finding and case.is_vulnerable:
            if case.expected_vulnerability:
                matched = any(case.expected_vulnerability in (f.title + " " + (f.root_cause or "")).lower() for f in findings)
            else:
                matched = True

        status = ""
        if case.is_vulnerable:
            if has_finding and matched:
                tp += 1
                status = "TP (HIT)"
            else:
                fn += 1
                status = "FN (MISSED)"
        else:
            if not has_finding:
                tn += 1
                status = "TN (CLEAN)"
            else:
                fp += 1
                status = "FP (FALSE ALARM)"

        print(f"[{status:^15}] {case.category:<12} | {case.name:<38} ({elapsed*1000:.1f}ms)")

    total = len(BENCHMARK_DATASET)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    avg_latency_ms = (sum(durations) / len(durations)) * 1000

    print("-" * 80)
    print("METRICS SUMMARY:")
    print(f"  Total Test Cases    : {total}")
    print(f"  True Positives (TP) : {tp}")
    print(f"  True Negatives (TN) : {tn}")
    print(f"  False Positives (FP): {fp}")
    print(f"  False Negatives (FN): {fn}")
    print(f"  Precision           : {precision * 100:.1f}%")
    print(f"  Recall              : {recall * 100:.1f}%")
    print(f"  F1 Score            : {f1 * 100:.1f}%")
    print(f"  False Positive Rate : {fpr * 100:.1f}%")
    print(f"  Avg Processing Time : {avg_latency_ms:.2f} ms")
    print("=" * 80)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "avg_latency_ms": avg_latency_ms,
    }


if __name__ == "__main__":
    metrics = evaluate_deterministic_benchmark()
    if metrics["fp"] > 0:
        print("\n[WARN] Benchmark detected false positives.")
        sys.exit(1)
    if metrics["f1"] < 0.90:
        print("\n[WARN] F1 score below 90% threshold.")
        sys.exit(1)
    print("\nBenchmark completed successfully with 0 false positives.")
