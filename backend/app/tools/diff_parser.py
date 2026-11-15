import re
from dataclasses import dataclass, field
from typing import List, Optional

HUNK_HEADER_PATTERN = re.compile(r"^@@\s*-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s*@@")
DIFF_GIT_PATTERN = re.compile(r"^diff\s+--git\s+(?:a/)?(\S+)\s+(?:b/)?(\S+)")
BINARY_DIFF_PATTERN = re.compile(r"^Binary\s+files\s+(?:a/)?(\S+)\s+and\s+(?:b/)?(\S+)\s+differ")


@dataclass
class DiffLine:
    line_number: Optional[int]
    content: str
    change_type: str  # 'added' | 'removed' | 'context'


@dataclass
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: List[DiffLine] = field(default_factory=list)


@dataclass
class DiffFile:
    old_path: str
    new_path: str
    hunks: List[DiffHunk] = field(default_factory=list)
    is_binary: bool = False
    is_deleted: bool = False
    is_new: bool = False


def parse_git_diff(diff_content: str) -> List[DiffFile]:
    """
    Parses unified git diff text into structured DiffFile representations.
    Accurately handles:
    - Multiple files and multiple hunks
    - Added (+), removed (-), and context ( ) lines
    - Accurate 1-based new_file line numbering
    - 'No newline at end of file' markers (ignored for line numbers)
    - Binary file diff markers (is_binary = True)
    - File creations (--- /dev/null) and deletions (+++ /dev/null)
    - Rename headers
    """
    if not diff_content or not diff_content.strip():
        return []

    files: List[DiffFile] = []
    current_file: Optional[DiffFile] = None
    current_hunk: Optional[DiffHunk] = None
    new_line_num = 0
    old_path = ""
    new_path = ""

    lines = diff_content.splitlines()
    for line in lines:
        # Check for diff --git header
        git_match = DIFF_GIT_PATTERN.match(line)
        if git_match:
            if current_file:
                if current_hunk:
                    current_file.hunks.append(current_hunk)
                    current_hunk = None
                files.append(current_file)
            old_path = git_match.group(1)
            new_path = git_match.group(2)
            current_file = DiffFile(old_path=old_path, new_path=new_path)
            continue

        # Check for binary file diff
        bin_match = BINARY_DIFF_PATTERN.match(line)
        if bin_match:
            if current_file:
                current_file.is_binary = True
            else:
                current_file = DiffFile(
                    old_path=bin_match.group(1),
                    new_path=bin_match.group(2),
                    is_binary=True,
                )
                files.append(current_file)
                current_file = None
            continue

        if "GIT binary patch" in line:
            if current_file:
                current_file.is_binary = True
            continue

        # Handle original file header (--- a/path or --- /dev/null)
        if line.startswith("--- a/") or line.startswith("--- /dev/null") or line.startswith("--- "):
            if line.startswith("--- a/"):
                old_path = line[6:].strip()
            elif line.startswith("--- /dev/null"):
                old_path = "/dev/null"
            else:
                old_path = line[4:].strip()

            if current_file and current_hunk:
                current_file.hunks.append(current_hunk)
                current_hunk = None
            if current_file:
                current_file.old_path = old_path
            continue

        # Handle target file header (+++ b/path or +++ /dev/null)
        if line.startswith("+++ b/") or line.startswith("+++ /dev/null") or line.startswith("+++ "):
            if line.startswith("+++ b/"):
                new_path = line[6:].strip()
            elif line.startswith("+++ /dev/null"):
                new_path = "/dev/null"
            else:
                new_path = line[4:].strip()

            if current_file is None:
                current_file = DiffFile(old_path=old_path or new_path, new_path=new_path)
            else:
                current_file.new_path = new_path

            if old_path == "/dev/null":
                current_file.is_new = True
            if new_path == "/dev/null":
                current_file.is_deleted = True
            continue

        # Hunk header: @@ -old_start,old_count +new_start,new_count @@ [optional heading]
        if line.startswith("@@"):
            if current_file and current_hunk:
                current_file.hunks.append(current_hunk)
                current_hunk = None

            match = HUNK_HEADER_PATTERN.match(line)
            if match:
                if current_file is None:
                    current_file = DiffFile(old_path=old_path or "code", new_path=new_path or "code")

                new_line_num = int(match.group(3))
                current_hunk = DiffHunk(
                    old_start=int(match.group(1)),
                    old_count=int(match.group(2) or 1),
                    new_start=int(match.group(3)),
                    new_count=int(match.group(4) or 1),
                )
            continue

        # Inside a hunk
        if current_hunk is not None:
            # Skip diff metadata markers such as '\ No newline at end of file'
            if line.startswith("\\"):
                continue

            # Added lines increment target line counter
            if line.startswith("+"):
                current_hunk.lines.append(
                    DiffLine(line_number=new_line_num, content=line[1:], change_type="added")
                )
                new_line_num += 1
            # Removed lines belong only to the old version; no line number in the new file
            elif line.startswith("-"):
                current_hunk.lines.append(
                    DiffLine(line_number=None, content=line[1:], change_type="removed")
                )
            # Unchanged context lines also advance the target file line counter
            else:
                # Handle leading space for context lines or bare line
                content = line[1:] if line.startswith(" ") else line
                current_hunk.lines.append(
                    DiffLine(
                        line_number=new_line_num,
                        content=content,
                        change_type="context",
                    )
                )
                new_line_num += 1

    # Flush any trailing hunk and file at EOF
    if current_file:
        if current_hunk:
            current_file.hunks.append(current_hunk)
        files.append(current_file)

    return files
