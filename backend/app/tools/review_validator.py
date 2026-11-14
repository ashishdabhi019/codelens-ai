from typing import List
from app.schemas.findings import Finding, ReviewResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def validate_and_merge(
    llm_result: ReviewResult,
    deterministic_findings: List[Finding],
) -> ReviewResult:
    """Merges and deduplicates findings, upgrading overall risk level when necessary."""
    seen = set()
    merged: List[Finding] = []

    # Priority 1: Seed with deterministic findings first so rule checks take precedence
    for f in deterministic_findings:
        key = (f.file, f.line, f.title[:30].lower())
        if key not in seen:
            seen.add(key)
            merged.append(f)

    # Priority 2: Append LLM findings, dropping any duplicates on the same line & topic
    for f in llm_result.findings:
        key = (f.file, f.line, f.title[:30].lower())
        if key not in seen:
            seen.add(key)
            merged.append(f)

    # Always present critical and high issues at the top of the report
    merged.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 4))

    # Safety rule: if ANY finding is critical or high, escalate the review's overall risk level
    if any(f.severity == "critical" for f in merged):
        risk_level = "critical"
    elif any(f.severity == "high" for f in merged):
        risk_level = "high"
    else:
        risk_level = llm_result.risk_level

    # If any findings exist, code cannot be silently approved
    overall_status = "changes_requested" if merged else llm_result.overall_status

    return llm_result.model_copy(
        update={
            "findings": merged,
            "deterministic_findings": deterministic_findings,
            "risk_level": risk_level,
            "overall_status": overall_status,
        }
    )
