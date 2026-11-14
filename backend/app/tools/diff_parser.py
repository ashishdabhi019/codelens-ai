import re
from dataclasses import dataclass, field
from typing import List, Optional

HUNK_HEADER_PATTERN = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


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


def parse_git_diff(diff_content: str) -> List[DiffFile]:
    """Parses unified diff text into structured DiffFile representations."""
    files: List[DiffFile] = []
    current_file: Optional[DiffFile] = None
    current_hunk: Optional[DiffHunk] = None
    new_line_num = 0
    old_path = ""

    for line in diff_content.splitlines():
        # Handle original file header (--- /dev/null indicates a newly created file)
        if line.startswith("--- a/") or line.startswith("--- /dev/null"):
            old_path = line[6:] if line.startswith("--- a/") else "/dev/null"
            if current_file and current_hunk:
                current_file.hunks.append(current_hunk)
                current_hunk = None
        # Handle target file header (+++ /dev/null indicates a deleted file)
        elif line.startswith("+++ b/") or line.startswith("+++ /dev/null"):
            new_path = line[6:] if line.startswith("+++ b/") else "/dev/null"
            if current_file:
                files.append(current_file)
            current_file = DiffFile(old_path=old_path, new_path=new_path)
        # Hunk header: @@ -old_start,old_count +new_start,new_count @@
        elif line.startswith("@@"):
            if current_file and current_hunk:
                current_file.hunks.append(current_hunk)
            match = HUNK_HEADER_PATTERN.match(line)
            if match and current_file:
                # We care about new_line_num so findings point to the right lines in the new code
                new_line_num = int(match.group(3))
                current_hunk = DiffHunk(
                    old_start=int(match.group(1)),
                    old_count=int(match.group(2) or 1),
                    new_start=int(match.group(3)),
                    new_count=int(match.group(4) or 1),
                )
        elif current_hunk is not None:
            # Added lines increment target line counter
            if line.startswith("+") and not line.startswith("+++"):
                current_hunk.lines.append(
                    DiffLine(line_number=new_line_num, content=line[1:], change_type="added")
                )
                new_line_num += 1
            # Removed lines belong only to the old version; no line number in the new file
            elif line.startswith("-") and not line.startswith("---"):
                current_hunk.lines.append(
                    DiffLine(line_number=None, content=line[1:], change_type="removed")
                )
            # Unchanged context lines also advance the target file line counter
            else:
                current_hunk.lines.append(
                    DiffLine(
                        line_number=new_line_num,
                        content=line[1:] if line else "",
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
