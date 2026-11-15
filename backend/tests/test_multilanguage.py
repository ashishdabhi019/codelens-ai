"""Tests for universal multi-language security detection in pattern_detector."""
from app.tools.diff_parser import parse_git_diff
from app.tools.pattern_detector import detect_risky_patterns


def test_javascript_sqli_template_literal():
    diff = """\
diff --git a/userRepo.ts b/userRepo.ts
--- a/userRepo.ts
+++ b/userRepo.ts
@@ -1,3 +1,3 @@
 const getUser = async (id: string) => {
+  const res = await db.query(`SELECT * FROM users WHERE id = ${id}`);
+  return res.rows[0];
 };
"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL Injection" in f.title and f.severity == "critical" for f in findings)


def test_javascript_xss_innerhtml():
    diff = """\
diff --git a/view.js b/view.js
--- a/view.js
+++ b/view.js
@@ -1,2 +1,2 @@
 function render(userInput) {
+  document.getElementById("output").innerHTML = userInput;
 }
"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("XSS" in f.title and f.severity == "critical" for f in findings)


def test_java_sqli_string_concat():
    diff = """\
diff --git a/UserDAO.java b/UserDAO.java
--- a/UserDAO.java
+++ b/UserDAO.java
@@ -1,3 +1,3 @@
 public User findUser(String name) {
+    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
     return parse(rs);
 }
"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL Injection" in f.title and f.severity == "critical" for f in findings)


def test_go_sqli_sprintf():
    diff = """\
diff --git a/user.go b/user.go
--- a/user.go
+++ b/user.go
@@ -1,3 +1,3 @@
 func Find(db *sql.DB, id string) error {
+    row := db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
     return row.Scan()
 }
"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("SQL Injection" in f.title and f.severity == "critical" for f in findings)


def test_c_buffer_overflow_strcpy():
    diff = """\
diff --git a/main.c b/main.c
--- a/main.c
+++ b/main.c
@@ -1,3 +1,3 @@
 void copy_name(char *input) {
+    strcpy(buffer, input);
 }
"""
    files = parse_git_diff(diff)
    findings = detect_risky_patterns(diff, files)
    assert any("buffer" in f.title.lower() and f.severity == "high" for f in findings)
