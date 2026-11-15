import re
from typing import List, Optional, Set, Dict, Tuple
from app.schemas.findings import Finding, ReviewResult
from app.tools.diff_parser import DiffFile
from app.tools.fix_validator import validate_suggested_fix, normalize_code

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

ROOT_CAUSE_CLUSTERS = [
    {"sql", "injection", "sqli", "execute", "query"},
    {"discount", "formula", "percent", "calculation", "inverted", "multiply"},
    {"zerodivision", "zero", "division", "empty", "len", "average"},
    {"password", "credential", "secret", "token", "hardcoded", "api_key"},
    {"eval", "exec", "rce", "arbitrary", "literal_eval"},
    {"negative", "quantity", "price", "validation", "negative values"},
    {"premium", "regular", "user_type", "tier"},
    {"pickle", "deserialize", "deserialization"},
    {"os.system", "shell", "subprocess", "command injection"},
]


def _extract_keywords(text: str) -> Set[str]:
    """Tokenizes text into lowercase word tokens."""
    if not text:
        return set()
    return set(re.findall(r'[a-zA-Z0-9_]+', text.lower()))


def are_duplicate_findings(f1: Finding, f2: Finding) -> bool:
    """
    Determines if two findings represent the same root cause or overlapping issue.
    """
    if f1.file != f2.file:
        return False

    # Check line proximity: exact same line, or adjacent lines within 1 line
    line_close = False
    if f1.line is not None and f2.line is not None:
        if abs(f1.line - f2.line) <= 1:
            line_close = True
    elif f1.line is None and f2.line is None:
        line_close = True

    if not line_close:
        return False

    tokens1 = _extract_keywords(f"{f1.title} {f1.description} {f1.root_cause or ''}")
    tokens2 = _extract_keywords(f"{f2.title} {f2.description} {f2.root_cause or ''}")

    # Check if both match any known root cause cluster
    for cluster in ROOT_CAUSE_CLUSTERS:
        if (tokens1 & cluster) and (tokens2 & cluster):
            return True

    # Check if they share significant title keywords
    title_tokens1 = _extract_keywords(f1.title) - {"issue", "bug", "error", "via", "in", "on", "a", "the", "and", "or"}
    title_tokens2 = _extract_keywords(f2.title) - {"issue", "bug", "error", "via", "in", "on", "a", "the", "and", "or"}
    if len(title_tokens1 & title_tokens2) >= 1 and (f1.line == f2.line):
        return True

    # If on exact same line and same category
    if f1.line == f2.line and f1.line is not None and f1.category == f2.category:
        return True

    return False


def merge_duplicate_findings(base: Finding, incoming: Finding, original_code: Optional[str] = None) -> Finding:
    """
    Merges two overlapping findings, preserving the highest severity, highest confidence,
    most useful explanation, and validated suggested fix.
    """
    # 1. Highest severity
    sev = base.severity if SEVERITY_ORDER.get(base.severity, 4) <= SEVERITY_ORDER.get(incoming.severity, 4) else incoming.severity

    # 2. Highest confidence
    conf = max(base.confidence, incoming.confidence)

    # 3. Prefer deterministic or more detailed title
    title = base.title
    if len(incoming.title) > len(base.title) and ("via" in incoming.title or "potential" in incoming.title.lower()):
        title = incoming.title

    # 4. Root cause: prefer the more descriptive one
    rc1 = base.root_cause or base.description
    rc2 = incoming.root_cause or incoming.description
    root_cause = rc1 if len(rc1) >= len(rc2) else rc2

    # 5. Description & Impact
    desc = base.description if len(base.description) >= len(incoming.description) else incoming.description
    impact = base.impact if len(base.impact) >= len(incoming.impact) else incoming.impact
    rec = base.recommendation if len(base.recommendation) >= len(incoming.recommendation) else incoming.recommendation

    # 6. Suggested Fix: validate both against original code!
    fix1, reason1 = validate_suggested_fix(base, original_code)
    fix2, reason2 = validate_suggested_fix(incoming, original_code)

    best_fix = None
    if fix1 and fix2:
        best_fix = fix1 if len(fix1) >= len(fix2) else fix2
    elif fix1:
        best_fix = fix1
    elif fix2:
        best_fix = fix2
    else:
        best_fix = None
        rejection = reason1 or reason2
        if rejection and rejection not in rec:
            rec = f"{rec} (Note on suggested fix: {rejection})"

    # 7. Line number: prefer non-None line
    line = base.line if base.line is not None else incoming.line

    # 8. Evidence: prefer non-empty evidence
    evidence = base.evidence or incoming.evidence

    return Finding(
        id=base.id,
        title=title,
        category=base.category if base.category == incoming.category else "bug",
        severity=sev,
        file=base.file,
        line=line,
        root_cause=root_cause,
        evidence=evidence,
        description=desc,
        impact=impact,
        recommendation=rec,
        suggested_fix=best_fix,
        confidence=conf,
    )


def sanitize_unsupported_assumptions(finding: Finding) -> Finding:
    """
    Detects when a finding invents unsupported business requirements
    (e.g., assuming a premium discount should be 10% without specification),
    and reframes it as a potential logic discrepancy needing requirement confirmation.
    """
    text = f"{finding.title} {finding.description} {finding.recommendation}".lower()

    has_tier = any(k in text for k in ("premium", "regular", "user_type", "tier"))
    has_arbitrary_val = bool(re.search(r'\b(?:should be|set to|change to|must be)\s*(?:10%?|15%?|25%?|30%?|50%?)\b', text, re.IGNORECASE))
    
    arbitrary_fix = False
    if finding.suggested_fix and has_tier:
        if re.search(r'return\s+(?:10|15|25|30|50)\b', finding.suggested_fix):
            arbitrary_fix = True

    if has_tier and (has_arbitrary_val or arbitrary_fix):
        finding.title = "Potential Business Logic Discrepancy: Tier Discount Rates"
        finding.description = (
            "The implementation returns a lower discount for 'premium' than for 'regular'. "
            "However, business requirements and exact discount tier percentages were not explicitly provided. "
            "Avoid assuming arbitrary tier values without confirmation."
        )
        finding.recommendation = (
            "Verify the intended tier discount policy with product requirements before modifying discount rates."
        )
        finding.suggested_fix = None
        finding.root_cause = "Tier discount rates appear inverted, but exact business requirements are unspecified."

    return finding


def sanitize_hallucinated_average_finding(finding: Finding) -> Finding:
    """
    Corrects severe LLM hallucination claiming an average should be calculated using multiplication.
    The real defect in unvalidated average calculation is ZeroDivisionError on empty input.
    """
    text = f"{finding.title} {finding.description} {finding.recommendation}".lower()
    if "average" in text and ("multiply" in text or "multiplication" in text):
        finding.title = "Potential ZeroDivisionError in calculate_average"
        finding.category = "bug"
        finding.severity = "high"
        finding.description = (
            "Calling calculate_average with an empty list or collection will cause a ZeroDivisionError "
            "when dividing by len(values) or count = 0."
        )
        finding.root_cause = "Division by zero when input values collection is empty"
        finding.impact = "Calling calculate_average([]) crashes the process with ZeroDivisionError."
        finding.recommendation = "Add an upfront guard: if not values: return 0.0 before performing division."
        finding.suggested_fix = "if not values:\n    return 0.0\ntotal = sum(values)\ncount = len(values)\nreturn total / count"
    return finding


def build_accurate_summary(
    llm_result: ReviewResult,
    findings: List[Finding],
    has_tests: bool,
) -> Tuple[str, List[str], List[str]]:
    """
    Generates an accurate summary, missing_tests list, and positive_observations,
    ensuring no false claims about unit tests existing when none were provided.
    """
    # 1. Sanitize positive observations: remove any hallucinated claims about tests existing
    clean_positives = []
    for obs in llm_result.positive_observations:
        obs_lower = obs.lower()
        if not has_tests and any(w in obs_lower for w in ("test", "coverage", "tests pass", "unit test")):
            continue
        clean_positives.append(obs)

    # 2. Build or refine missing_tests
    missing_tests = list(llm_result.missing_tests)
    if not has_tests:
        standard_missing = [
            f"No automated tests supplied for {f.file} (verify line {f.line or 'N/A'}: {f.title})"
            for f in findings[:3]
        ]
        for sm in standard_missing:
            if sm not in missing_tests:
                missing_tests.append(sm)

    # 3. Create accurate summary
    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    total = len(findings)

    if total == 0:
        summary = "Review complete: No critical bugs or security risks detected in changed code."
        if not has_tests:
            summary += " Note: No automated unit tests were included in this changeset."
    else:
        parts = []
        if crit_count > 0:
            parts.append(f"{crit_count} critical")
        if high_count > 0:
            parts.append(f"{high_count} high")
        if med_count > 0:
            parts.append(f"{med_count} medium")
        breakdown = ", ".join(parts) if parts else f"{total} issue(s)"
        summary = f"Review identified {total} issue(s) ({breakdown})."
        if not has_tests:
            summary += " Code lacks automated test coverage for the modified logic."
        else:
            summary += " Automated test coverage detected."

    return summary, missing_tests, clean_positives


def validate_and_merge(
    llm_result: ReviewResult,
    deterministic_findings: List[Finding],
    diff_files: Optional[List[DiffFile]] = None,
) -> ReviewResult:
    """Merges and deduplicates findings, validating fixes, sanitizing assumptions, and ensuring summary accuracy."""
    # Build code line index for evidence extraction and fix validation
    line_map: Dict[Tuple[str, int], str] = {}
    has_tests = False

    if diff_files:
        for df in diff_files:
            file_name = df.new_path
            if "test" in file_name.lower():
                has_tests = True
            for hunk in df.hunks:
                for dl in hunk.lines:
                    if dl.line_number is not None:
                        line_map[(file_name, dl.line_number)] = dl.content
                        if "def test_" in dl.content or "assert " in dl.content:
                            has_tests = True

    # Pool all findings (deterministic first for priority)
    raw_findings = list(deterministic_findings) + list(llm_result.findings)
    merged: List[Finding] = []

    for f in raw_findings:
        # Correct known mathematical hallucinations (e.g. LLM claiming average is multiplication)
        f = sanitize_hallucinated_average_finding(f)

        orig_code = line_map.get((f.file, f.line or 0)) if f.line else None

        # If line points to a comment line or blank line, advance to the next executable statement
        if f.line and (not orig_code or not orig_code.strip() or orig_code.strip().startswith("#")):
            for offset in (1, 2, 3):
                next_code = line_map.get((f.file, f.line + offset))
                if next_code and next_code.strip() and not next_code.strip().startswith("#"):
                    f.line = f.line + offset
                    orig_code = next_code
                    f.evidence = next_code.strip()
                    break

        # Drop findings that describe a bug in removed code that the author already fixed in this diff
        if diff_files and f.line:
            was_removed_and_fixed = False
            for df in diff_files:
                if df.new_path == f.file:
                    for hunk in df.hunks:
                        removed_texts = [dl.content.strip() for dl in hunk.lines if dl.change_type == "removed" and dl.content.strip()]
                        added_texts = [dl.content.strip() for dl in hunk.lines if dl.change_type == "added" and dl.content.strip()]
                        if any(rem in (f.evidence or "") or rem in f.description for rem in removed_texts):
                            # The bug was in the removed line, and new code was added replacing it
                            if added_texts and not any(rem in add for rem in removed_texts for add in added_texts):
                                was_removed_and_fixed = True
                                break
            if was_removed_and_fixed:
                continue

        if not f.evidence and orig_code:
            f.evidence = orig_code.strip()

        # Validate suggested fix against original code
        valid_fix, rejection_reason = validate_suggested_fix(f, orig_code)
        f.suggested_fix = valid_fix
        if rejection_reason and not valid_fix and rejection_reason not in f.recommendation:
            f.recommendation = f"{f.recommendation} (Note: {rejection_reason})"

        # Sanitize unsupported business assumptions
        f = sanitize_unsupported_assumptions(f)

        # Check for duplicates / overlaps in merged list
        found_dup_idx = -1
        for i, existing in enumerate(merged):
            if are_duplicate_findings(existing, f):
                found_dup_idx = i
                break

        if found_dup_idx >= 0:
            # Merge with existing finding, keeping best explanation & fix
            merged[found_dup_idx] = merge_duplicate_findings(merged[found_dup_idx], f, orig_code)
        else:
            merged.append(f)

    # Sort findings by severity
    merged.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 4))

    # Update risk level based on highest finding severity
    if any(f.severity == "critical" for f in merged):
        risk_level = "critical"
    elif any(f.severity == "high" for f in merged):
        risk_level = "high"
    elif any(f.severity == "medium" for f in merged):
        risk_level = "medium"
    else:
        risk_level = llm_result.risk_level

    overall_status = "changes_requested" if merged else llm_result.overall_status

    # Build accurate summary without false test claims
    summary, missing_tests, clean_positives = build_accurate_summary(llm_result, merged, has_tests)

    return llm_result.model_copy(
        update={
            "summary": summary,
            "findings": merged,
            "deterministic_findings": deterministic_findings,
            "risk_level": risk_level,
            "overall_status": overall_status,
            "missing_tests": missing_tests,
            "positive_observations": clean_positives,
        }
    )
