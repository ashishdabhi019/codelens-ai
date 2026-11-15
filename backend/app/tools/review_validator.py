import os
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
    """Determines if two findings represent the same root cause or overlapping issue."""
    if f1.file != f2.file:
        return False

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

    for cluster in ROOT_CAUSE_CLUSTERS:
        if (tokens1 & cluster) and (tokens2 & cluster):
            return True

    title_tokens1 = _extract_keywords(f1.title) - {"issue", "bug", "error", "via", "in", "on", "a", "the", "and", "or"}
    title_tokens2 = _extract_keywords(f2.title) - {"issue", "bug", "error", "via", "in", "on", "a", "the", "and", "or"}
    if len(title_tokens1 & title_tokens2) >= 1 and (f1.line == f2.line):
        return True

    if f1.line == f2.line and f1.line is not None and f1.category == f2.category:
        return True

    return False


def merge_duplicate_findings(base: Finding, incoming: Finding, original_code: Optional[str] = None) -> Finding:
    """
    Merges two overlapping findings, preserving the highest severity, highest confidence,
    most useful explanation, and validated suggested fix.
    """
    sev = base.severity if SEVERITY_ORDER.get(base.severity, 4) <= SEVERITY_ORDER.get(incoming.severity, 4) else incoming.severity
    conf = max(base.confidence, incoming.confidence)

    title = base.title
    if len(incoming.title) > len(base.title) and ("via" in incoming.title or "potential" in incoming.title.lower()):
        title = incoming.title

    rc1 = base.root_cause or base.description
    rc2 = incoming.root_cause or incoming.description
    root_cause = rc1 if len(rc1) >= len(rc2) else rc2

    desc = base.description if len(base.description) >= len(incoming.description) else incoming.description
    impact = base.impact if len(base.impact) >= len(incoming.impact) else incoming.impact
    rec = base.recommendation if len(base.recommendation) >= len(incoming.recommendation) else incoming.recommendation

    val1 = validate_suggested_fix(base, original_code, file_path=base.file)
    val2 = validate_suggested_fix(incoming, original_code, file_path=incoming.file)

    best_fix = None
    fix_status = "proposed"
    if val1[0] and val2[0]:
        if len(val1[0]) >= len(val2[0]):
            best_fix = val1[0]
            fix_status = val1.fix_status
        else:
            best_fix = val2[0]
            fix_status = val2.fix_status
    elif val1[0]:
        best_fix = val1[0]
        fix_status = val1.fix_status
    elif val2[0]:
        best_fix = val2[0]
        fix_status = val2.fix_status
    else:
        best_fix = None
        fix_status = "rejected"
        rejection = val1[1] or val2[1]
        if rejection and rejection not in rec:
            rec = f"{rec} (Note on suggested fix: {rejection})"

    line = base.line if base.line is not None else incoming.line
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
        fix_verification_status=fix_status,
    )


def sanitize_unsupported_assumptions(finding: Finding) -> Finding:
    """
    Detects when a finding invents unsupported business requirements
    (e.g., assuming a premium discount should be 10% without specification),
    and reframes it as a potential logic discrepancy needing requirement confirmation.
    """
    text = f"{finding.title} {finding.description} {finding.recommendation}".lower()

    has_tier = any(k in text for k in ("premium", "regular", "user_type", "tier", "gold", "silver", "vip", "cashback"))
    has_arbitrary_val = bool(re.search(r'\b(?:should be|set to|change to|must be)\s*(?:10%?|15%?|25%?|30%?|50%?|12\.5%?)\b', text, re.IGNORECASE))

    arbitrary_fix = False
    if finding.suggested_fix and has_tier:
        if re.search(r'return\s+(?:10|15|25|30|50|0\.125)\b', finding.suggested_fix):
            arbitrary_fix = True

    if has_tier and (has_arbitrary_val or arbitrary_fix):
        finding.title = "Potential Business Logic Discrepancy: Tier Discount Rates"
        finding.description = (
            "The implementation returns a hardcoded or lower reward/discount for this user tier. "
            "However, business requirements and exact discount tier percentages were not explicitly provided. "
            "Avoid assuming arbitrary tier values without confirmation."
        )
        finding.recommendation = (
            "Verify the intended tier discount policy with product requirements before modifying discount rates."
        )
        finding.suggested_fix = None
        finding.fix_verification_status = "rejected"
        finding.root_cause = "Tier discount rates appear arbitrary, but exact business requirements are unspecified."

    return finding


def validate_source_evidence(
    finding: Finding,
    diff_files: Optional[List[DiffFile]],
    file_lines: Dict[str, Dict[int, str]],
    file_all_code: Dict[str, str],
) -> Tuple[bool, Optional[Finding], Optional[str]]:
    """
    Strictly validates finding against actual source code and diff.
    Verifies:
    1. Referenced file exists in diff.
    2. Reported line number exists in file.
    3. Evidence corresponds to the actual source line.
    4. Rejects false ZeroDivision claims where no division operator exists or denominator cannot be zero.
    5. Rejects false SQL injection where query is parameterized.
    6. Rejects false eval on ast.literal_eval.
    7. Rejects false credential on os.getenv / environment lookup.
    """
    if not diff_files:
        # If no diff files provided, cannot cross-check diff structure
        return True, finding, None

    # Step 1: Match file in diff
    matched_file_key = None
    finding_file_base = os.path.basename(finding.file)
    for df_key in file_lines.keys():
        if df_key == finding.file or os.path.basename(df_key) == finding_file_base:
            matched_file_key = df_key
            break

    if not matched_file_key:
        return False, None, f"Referenced file '{finding.file}' does not exist in the submitted diff."

    # Normalize file path in finding to match diff
    finding.file = matched_file_key
    lines_in_file = file_lines[matched_file_key]
    full_code = file_all_code.get(matched_file_key, "")

    # Step 2: Line number verification
    if finding.line is not None:
        if finding.line not in lines_in_file:
            # Check if evidence matches another line in this file
            if finding.evidence and finding.evidence.strip():
                norm_ev = normalize_code(finding.evidence)
                matched_line = None
                for l_num, l_content in lines_in_file.items():
                    if norm_ev and (norm_ev in normalize_code(l_content) or normalize_code(l_content) in norm_ev):
                        matched_line = l_num
                        break
                if matched_line:
                    finding.line = matched_line
                else:
                    return False, None, f"Line {finding.line} does not exist in '{finding.file}' and evidence cannot be verified."

    # Step 3: Evidence verification against actual code
    actual_code = lines_in_file.get(finding.line, "") if finding.line else ""
    if finding.evidence and finding.evidence.strip():
        norm_ev = normalize_code(finding.evidence)
        norm_actual = normalize_code(actual_code)

        # Check surrounding +/- 2 lines if line offset slightly
        if norm_actual and norm_ev not in norm_actual and norm_actual not in norm_ev:
            nearby_match = False
            if finding.line:
                for offset in (-2, -1, 1, 2):
                    adj_code = lines_in_file.get(finding.line + offset, "")
                    if norm_ev in normalize_code(adj_code) or normalize_code(adj_code) in norm_ev:
                        finding.line = finding.line + offset
                        actual_code = adj_code
                        nearby_match = True
                        break
            if not nearby_match and norm_ev not in normalize_code(full_code):
                # Evidence does not exist in the file at all -> Hallucinated evidence
                return False, None, f"Evidence '{finding.evidence.strip()}' does not exist in file '{finding.file}'."
    elif actual_code:
        # Populate actual evidence from source code (never invent fake code)
        finding.evidence = actual_code.strip()

    # Step 4: Semantic sanity checks on specific vulnerability claims

    # 4a. ZeroDivisionError verification
    text = f"{finding.title} {finding.description}".lower()
    if "zerodivision" in text or "division by zero" in text:
        context_window = actual_code
        if finding.line:
            surrounding = [lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]
            context_window = " ".join(surrounding)

        # Check if code actually contains division / modulo operators
        has_division = bool(re.search(r'/(?!/|\*)|\bdiv\b|%', context_window))
        if not has_division:
            # Code does NOT divide! E.g. multiplication 'total_spend * 0.125'
            return False, None, f"ZeroDivisionError finding rejected: code at line {finding.line} does not contain division."

        # Check if denominator is a non-zero literal constant (e.g. / 100, / 2, / 1000)
        literal_denom = re.search(r'/\s*([0-9]+(?:\.[0-9]+)?)\b', actual_code)
        if literal_denom and float(literal_denom.group(1)) != 0.0:
            return False, None, f"ZeroDivisionError finding rejected: denominator is non-zero literal {literal_denom.group(1)}."

        # Check if division is already guarded by an upfront check
        if any(guard in full_code.lower() for guard in ("if not ", "if len(", "if count ==", "== 0: return", "<= 0: return")):
            # If the specific function already has a guard on the same variable, reject
            m_len = re.search(r'/\s*len\(\s*(\w+)\s*\)', actual_code)
            if m_len:
                var = m_len.group(1)
                if f"if not {var}" in full_code or f"len({var}) == 0" in full_code or f"len({var}) <= 0" in full_code:
                    return False, None, f"ZeroDivisionError finding rejected: guarded against empty {var}."

    # 4b. SQL injection check: do not flag safe parameterized queries
    if ("sql injection" in text or "sqli" in text) and actual_code:
        # Parameterized query with placeholders (?, %s, $1) and tuple/list argument
        is_safe_param = bool(
            re.search(r'\.execute\(\s*["\'][^"\']*(?:\?|%s|\$1)[^"\']*["\']\s*,\s*(?:\([^)]+\)|\[[^\]]+\]|\w+)\s*\)', actual_code)
        )
        has_fstring_or_concat = bool(re.search(r'f["\']|\.format\(|\+\s*\w+', actual_code))
        if is_safe_param and not has_fstring_or_concat:
            return False, None, f"SQL injection finding rejected: parameterized query on line {finding.line} is safe."

    # 4c. Eval check: do not flag ast.literal_eval
    if "eval" in text and "literal_eval" in actual_code and "ast.literal_eval" in actual_code:
        return False, None, f"eval finding rejected: ast.literal_eval is safe."

    # 4d. Hardcoded credential check: do not flag os.getenv / os.environ
    if any(k in text for k in ("hardcoded", "credential", "secret", "api_key")) and actual_code:
        if "os.getenv(" in actual_code or "os.environ" in actual_code or "environ.get(" in actual_code:
            return False, None, f"Hardcoded credential finding rejected: reading from environment variable."

    return True, finding, None


def build_accurate_summary(
    llm_result: ReviewResult,
    findings: List[Finding],
    has_tests: bool,
    diff_files: Optional[List[DiffFile]] = None,
    unverified_count: int = 0,
) -> Tuple[str, List[str], List[str]]:
    """
    Generates an accurate summary, missing_tests list, and positive_observations,
    ensuring no false claims about unit tests existing when none were provided.
    """
    clean_positives = []
    for obs in llm_result.positive_observations:
        obs_lower = obs.lower()
        if not has_tests and any(w in obs_lower for w in ("test", "coverage", "tests pass", "unit test")):
            continue
        clean_positives.append(obs)

    missing_tests = list(llm_result.missing_tests)
    if not has_tests:
        if findings:
            standard_missing = [
                f"No automated tests supplied for {f.file} (verify line {f.line or 'N/A'}: {f.title})"
                for f in findings[:3]
            ]
            for sm in standard_missing:
                if sm not in missing_tests:
                    missing_tests.append(sm)
        elif diff_files:
            for df in diff_files:
                if df.new_path and df.new_path != "/dev/null":
                    missing_tests.append(f"No unit tests supplied for {df.new_path} — logic lacks automated test coverage.")

    crit_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    med_count = sum(1 for f in findings if f.severity == "medium")
    total = len(findings)

    if total == 0:
        if not llm_result.llm_available or getattr(llm_result, "partial_analysis", False):
            summary = "Static inspection complete. LLM semantic analysis was offline (partial review)."
        else:
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
    """
    Validates, deduplicates, and merges findings across static and semantic analysis.
    Performs source evidence verification, fix validation, and summary generation.
    """
    line_map: Dict[Tuple[str, int], str] = {}
    file_lines: Dict[str, Dict[int, str]] = {}
    file_all_code: Dict[str, str] = {}
    has_tests = False

    if diff_files:
        for df in diff_files:
            file_name = df.new_path
            if "test" in file_name.lower():
                has_tests = True

            lines_dict: Dict[int, str] = {}
            full_lines: List[str] = []

            for hunk in df.hunks:
                for dl in hunk.lines:
                    if dl.line_number is not None:
                        line_map[(file_name, dl.line_number)] = dl.content
                        lines_dict[dl.line_number] = dl.content
                        full_lines.append(dl.content)
                        if "def test_" in dl.content or "assert " in dl.content:
                            has_tests = True

            file_lines[file_name] = lines_dict
            file_all_code[file_name] = "\n".join(full_lines)

    # Pool raw findings: deterministic first
    raw_findings = list(deterministic_findings) + list(llm_result.findings)
    merged: List[Finding] = []
    unverified_count = 0

    for f in raw_findings:
        # Step A: Validate finding against source code and diff
        valid, validated_f, reject_reason = validate_source_evidence(
            f, diff_files, file_lines, file_all_code
        )
        if not valid or validated_f is None:
            unverified_count += 1
            continue

        f = validated_f
        orig_code = line_map.get((f.file, f.line or 0)) if f.line else None

        # Step B: Drop findings that describe a bug in removed code that the author already fixed
        if diff_files and f.line:
            was_removed_and_fixed = False
            for df in diff_files:
                if df.new_path == f.file:
                    for hunk in df.hunks:
                        removed_texts = [dl.content.strip() for dl in hunk.lines if dl.change_type == "removed" and dl.content.strip()]
                        added_texts = [dl.content.strip() for dl in hunk.lines if dl.change_type == "added" and dl.content.strip()]
                        if any(rem in (f.evidence or "") or rem in f.description for rem in removed_texts):
                            if added_texts and not any(rem in add for rem in removed_texts for add in added_texts):
                                was_removed_and_fixed = True
                                break
            if was_removed_and_fixed:
                continue

        # Step C: Validate suggested fix against original code & language syntax
        val_res = validate_suggested_fix(f, orig_code, file_path=f.file)
        f.suggested_fix = val_res[0]
        f.fix_verification_status = val_res.fix_status
        if val_res[1] and not val_res[0] and val_res[1] not in f.recommendation:
            f.recommendation = f"{f.recommendation} (Note: {val_res[1]})"

        # Step D: Sanitize unsupported business assumptions (e.g. arbitrary discount rates)
        f = sanitize_unsupported_assumptions(f)

        # Step E: Deduplication
        found_dup_idx = -1
        for i, existing in enumerate(merged):
            if are_duplicate_findings(existing, f):
                found_dup_idx = i
                break

        if found_dup_idx >= 0:
            merged[found_dup_idx] = merge_duplicate_findings(merged[found_dup_idx], f, orig_code)
        else:
            merged.append(f)

    # Sort findings by severity
    merged.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 4))

    # Determine risk level
    if any(f.severity == "critical" for f in merged):
        risk_level = "critical"
    elif any(f.severity == "high" for f in merged):
        risk_level = "high"
    elif any(f.severity == "medium" for f in merged):
        risk_level = "medium"
    else:
        # If partial analysis and no findings, do not claim low risk unconditionally
        if getattr(llm_result, "partial_analysis", False) or not llm_result.llm_available:
            risk_level = "medium"
        else:
            risk_level = llm_result.risk_level

    # Determine overall status
    if merged:
        overall_status = "changes_requested"
    elif getattr(llm_result, "partial_analysis", False) or not llm_result.llm_available:
        overall_status = "needs_attention"
    else:
        overall_status = llm_result.overall_status

    # Build accurate summary
    summary, missing_tests, clean_positives = build_accurate_summary(
        llm_result, merged, has_tests, diff_files=diff_files, unverified_count=unverified_count
    )

    is_partial = getattr(llm_result, "partial_analysis", False) or not llm_result.llm_available

    return llm_result.model_copy(
        update={
            "summary": summary,
            "findings": merged,
            "deterministic_findings": deterministic_findings,
            "risk_level": risk_level,
            "overall_status": overall_status,
            "missing_tests": missing_tests,
            "positive_observations": clean_positives,
            "partial_analysis": is_partial,
            "unverified_findings_count": unverified_count,
        }
    )
