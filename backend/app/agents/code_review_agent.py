from app.schemas.review import ReviewRequest
from app.schemas.findings import ReviewResult
from app.tools.diff_parser import parse_git_diff
from app.tools.code_inspector import inspect_changed_code
from app.tools.pattern_detector import detect_risky_patterns
from app.tools.review_validator import validate_and_merge
from app.services.llm_service import generate_review
from app.config import settings


async def run_review(request: ReviewRequest) -> ReviewResult:
    """Orchestrates diff parsing, pattern detection, LLM analysis, and result merging."""
    # Guardrail: reject oversized payloads early to prevent memory spikes and Ollama context blowups
    diff_bytes = len(request.diff_content.encode("utf-8"))
    if diff_bytes > settings.max_diff_size_bytes:
        raise ValueError(
            f"Diff exceeds maximum size limit ({diff_bytes} > {settings.max_diff_size_bytes} bytes)"
        )

    # Step 1: Parse the unified diff into structured file hunks
    diff_files = parse_git_diff(request.diff_content)
    if not diff_files:
        raise ValueError("Could not parse any file changes from the provided diff")

    # Step 2: Extract changed sections with surrounding context for prompt feeding
    code_sections = inspect_changed_code(diff_files)

    # Step 3: Run deterministic security rules (SQLi, eval, hardcoded secrets)
    # These always run first and carry 100% confidence, even if the LLM is completely offline
    deterministic_findings = detect_risky_patterns(request.diff_content, diff_files)

    # Step 4: Dispatch semantic analysis to Ollama (or fallback gracefully if unreachable)
    llm_result, _ = await generate_review(
        code_sections=code_sections,
        focus=request.focus,
        language=request.language or "auto-detect",
        additional_instructions=request.additional_instructions or "",
        files_reviewed=len(diff_files),
    )

    # Step 5: Merge findings, deduplicate matches, validate fixes, and escalate risk level if needed
    return validate_and_merge(llm_result, deterministic_findings, diff_files=diff_files)
