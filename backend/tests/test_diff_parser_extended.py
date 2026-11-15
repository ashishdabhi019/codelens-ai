"""Tests for extended diff parser behaviors: no-newline markers, binary patches, multi-hunk offsets."""
import pytest
from app.tools.diff_parser import parse_git_diff


def test_no_newline_marker_ignored():
    """Diffs containing '\\ No newline at end of file' must not treat marker as source line or increment line counter."""
    diff = """\
diff --git a/script.py b/script.py
--- a/script.py
+++ b/script.py
@@ -1,2 +1,3 @@
 print("one")
+print("two")
+print("three")
\\ No newline at end of file
"""
    files = parse_git_diff(diff)
    assert len(files) == 1
    hunk = files[0].hunks[0]
    # Check that '\ No newline' is not included in lines
    for dl in hunk.lines:
        assert "\\ No newline" not in dl.content
    added_lines = [dl for dl in hunk.lines if dl.change_type == "added"]
    assert len(added_lines) == 2
    assert added_lines[0].line_number == 2
    assert added_lines[1].line_number == 3


def test_binary_file_diff_detected():
    """Binary file diff indicators must mark is_binary=True and not crash."""
    diff = """\
diff --git a/image.png b/image.png
new file mode 100644
index 0000000..1234567
Binary files /dev/null and b/image.png differ
"""
    files = parse_git_diff(diff)
    assert len(files) == 1
    assert files[0].is_binary is True
    assert files[0].new_path == "image.png"


def test_multi_hunk_line_offsets():
    """Accurately calculates line numbers across multiple hunks in a file."""
    diff = """\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -5,3 +5,4 @@
 line5
 line6
+line7_added
 line8
@@ -20,2 +21,3 @@
 line20
+line22_added
 line21
"""
    files = parse_git_diff(diff)
    assert len(files) == 1
    hunks = files[0].hunks
    assert len(hunks) == 2

    # Hunk 1: starts at new_start = 5
    added_hunk1 = [dl for dl in hunks[0].lines if dl.change_type == "added"]
    assert len(added_hunk1) == 1
    assert added_hunk1[0].line_number == 7
    assert added_hunk1[0].content == "line7_added"

    # Hunk 2: starts at new_start = 21
    added_hunk2 = [dl for dl in hunks[1].lines if dl.change_type == "added"]
    assert len(added_hunk2) == 1
    assert added_hunk2[0].line_number == 22
    assert added_hunk2[0].content == "line22_added"


def test_new_and_deleted_files():
    """Distinguishes new files (--- /dev/null) and deleted files (+++ /dev/null)."""
    diff = """\
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+print("new")
+print("file")
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,2 +0,0 @@
-print("deleted")
-print("file")
"""
    files = parse_git_diff(diff)
    assert len(files) == 2
    assert files[0].is_new is True
    assert files[0].new_path == "new.py"
    assert files[1].is_deleted is True
    assert files[1].new_path == "/dev/null"
