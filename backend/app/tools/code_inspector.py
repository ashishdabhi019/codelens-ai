from typing import Dict, List
from app.tools.diff_parser import DiffFile


def inspect_changed_code(diff_files: List[DiffFile]) -> Dict[str, str]:
    """Formats changed hunks with line-number context for LLM prompt ingestion."""
    sections_by_file: Dict[str, str] = {}

    for diff_file in diff_files:
        hunk_blocks: List[str] = []
        for hunk in diff_file.hunks:
            if not any(line.change_type == "added" for line in hunk.lines):
                continue

            header = f"# Lines {hunk.new_start}-{hunk.new_start + hunk.new_count}:\n"
            body = []
            for dl in hunk.lines:
                prefix = "+" if dl.change_type == "added" else ("-" if dl.change_type == "removed" else " ")
                ln = str(dl.line_number) if dl.line_number is not None else "?"
                body.append(f"  {prefix} [{ln}] {dl.content}")

            hunk_blocks.append(header + "\n".join(body))

        if hunk_blocks:
            sections_by_file[diff_file.new_path] = "\n\n".join(hunk_blocks)

    return sections_by_file
