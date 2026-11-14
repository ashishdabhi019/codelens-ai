"""Tests for parse_git_diff."""
import pytest
from app.tools.diff_parser import parse_git_diff


SINGLE_FILE_DIFF = """\
diff --git a/calculator.py b/calculator.py
index 1234567..abcdef0 100644
--- a/calculator.py
+++ b/calculator.py
@@ -1,5 +1,6 @@
 def add(a, b):
-    return a - b
+    return a + b
+
+# fixed
"""

MULTI_FILE_DIFF = """\
diff --git a/foo.py b/foo.py
index 0000001..0000002 100644
--- a/foo.py
+++ b/foo.py
@@ -1,3 +1,4 @@
 x = 1
+y = 2
 z = 3
diff --git a/bar.py b/bar.py
index 0000003..0000004 100644
--- a/bar.py
+++ b/bar.py
@@ -1,2 +1,3 @@
 def hello():
+    print("hello")
     pass
"""

EMPTY_DIFF = ""
GARBAGE_DIFF = "this is not a diff at all\njust random text"


def test_single_file_diff():
    files = parse_git_diff(SINGLE_FILE_DIFF)
    assert len(files) == 1
    f = files[0]
    assert f.new_path == "calculator.py"
    assert f.old_path == "calculator.py"
    assert len(f.hunks) == 1
    hunk = f.hunks[0]
    added = [l for l in hunk.lines if l.change_type == "added"]
    removed = [l for l in hunk.lines if l.change_type == "removed"]
    assert len(added) >= 1
    assert len(removed) >= 1
    assert any("return a + b" in l.content for l in added)


def test_multi_file_diff():
    files = parse_git_diff(MULTI_FILE_DIFF)
    assert len(files) == 2
    paths = {f.new_path for f in files}
    assert "foo.py" in paths
    assert "bar.py" in paths
    # Each file should have exactly 1 hunk
    for f in files:
        assert len(f.hunks) == 1
    # foo.py should have y=2 as added
    foo = next(f for f in files if f.new_path == "foo.py")
    added = [l for h in foo.hunks for l in h.lines if l.change_type == "added"]
    assert any("y = 2" in l.content for l in added)


def test_empty_diff_returns_empty_list():
    files = parse_git_diff(EMPTY_DIFF)
    assert files == []


def test_garbage_diff_returns_empty_list():
    files = parse_git_diff(GARBAGE_DIFF)
    assert files == []


def test_line_numbers_assigned_to_added_lines():
    files = parse_git_diff(SINGLE_FILE_DIFF)
    hunk = files[0].hunks[0]
    added = [l for l in hunk.lines if l.change_type == "added"]
    for l in added:
        assert l.line_number is not None
        assert l.line_number >= 1


def test_removed_lines_have_no_line_number():
    files = parse_git_diff(SINGLE_FILE_DIFF)
    hunk = files[0].hunks[0]
    removed = [l for l in hunk.lines if l.change_type == "removed"]
    for l in removed:
        assert l.line_number is None
