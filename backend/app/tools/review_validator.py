import os
import ast
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


def _get_enclosing_ast_function(full_code: str, line: Optional[int]) -> Optional[ast.AST]:
    """Finds the innermost AST function or async function node containing the given line number."""
    if not line or not full_code:
        return None
    try:
        tree = ast.parse(full_code)
        target_fn = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_lineno = getattr(node, "end_lineno", node.lineno + 100)
                if node.lineno <= line <= end_lineno:
                    if target_fn is None or (node.lineno >= target_fn.lineno and end_lineno <= getattr(target_fn, "end_lineno", 10000)):
                        target_fn = node
        return target_fn
    except Exception:
        return None


def _verify_vulnerability_claim(
    finding: Finding,
    actual_code: str,
    lines_in_file: Dict[int, str],
    full_code: str,
    file_path: str,
) -> Tuple[bool, Optional[str]]:
    """
    Verifies that the claimed vulnerability type is semantically supported
    by the code at the reported location and its enclosing function/scope.
    """
    claim_text = f"{finding.title} {finding.description} {finding.root_cause or ''}".lower()
    title_lower = finding.title.lower()
    rc_lower = (finding.root_cause or "").lower()
    is_python = file_path.endswith(".py") or "python" in file_path.lower()
    fn_node = _get_enclosing_ast_function(full_code, finding.line) if is_python else None

    # 1. SQL Injection Verification
    if "sql injection" in title_lower or "sqli" in title_lower or "sql injection" in rc_lower:
        if is_python and fn_node is not None:
            # 1a. Check if enclosing function contains ANY database calls or SQL keywords
            all_calls = [n for n in ast.walk(fn_node) if isinstance(n, ast.Call)]
            has_db_calls = False
            for call in all_calls:
                func_name = ""
                if isinstance(call.func, ast.Name):
                    func_name = call.func.id.lower()
                elif isinstance(call.func, ast.Attribute):
                    func_name = call.func.attr.lower()
                if func_name in ("execute", "executemany", "raw", "select", "query", "cursor", "connect"):
                    has_db_calls = True
                    break

            sql_kw_regex = re.compile(
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE\s+TABLE)\b', re.IGNORECASE
            )
            fn_source = ast.unparse(fn_node) if hasattr(ast, "unparse") else ""
            has_sql_keywords = bool(sql_kw_regex.search(fn_source))

            if not has_db_calls and not has_sql_keywords:
                return False, f"SQL injection finding rejected: function at line {finding.line} contains no SQL queries or database operations."

            # 1b. Check if dynamic query construction exists in this function
            has_dynamic_sql = False
            for n in ast.walk(fn_node):
                if isinstance(n, ast.JoinedStr):
                    joined_str_repr = ast.unparse(n) if hasattr(ast, "unparse") else ""
                    if sql_kw_regex.search(joined_str_repr) and any(isinstance(v, ast.FormattedValue) for v in n.values):
                        has_dynamic_sql = True
                        break
                elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
                    bin_repr = ast.unparse(n) if hasattr(ast, "unparse") else ""
                    if sql_kw_regex.search(bin_repr):
                        has_dynamic_sql = True
                        break
                elif isinstance(n, ast.Call):
                    if isinstance(n.func, ast.Attribute) and n.func.attr == "format":
                        fmt_repr = ast.unparse(n) if hasattr(ast, "unparse") else ""
                        if sql_kw_regex.search(fmt_repr):
                            has_dynamic_sql = True
                            break

            # 1c. If no dynamic SQL construction, check if execute calls are parameterized
            if not has_dynamic_sql:
                exec_calls = [
                    c for c in all_calls
                    if isinstance(c.func, ast.Attribute) and c.func.attr in ("execute", "executemany")
                ]
                if exec_calls:
                    all_safe_params = True
                    for ec in exec_calls:
                        if not ec.args:
                            continue
                        first_arg = ec.args[0]
                        # Safe if first argument is a literal string with ?, %s, or $1 placeholders
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            if re.search(r'(\?|%s|\$1)', first_arg.value):
                                if len(ec.args) >= 2 or ec.keywords:
                                    continue
                        all_safe_params = False
                        break
                    if all_safe_params:
                        return False, f"SQL injection finding rejected: all queries in function at line {finding.line} use safe parameterized placeholders."
        else:
            context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-5, 6)]) if finding.line else actual_code
            sql_kw = re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b', context, re.IGNORECASE)
            db_call = re.search(r'\b(query|execute|raw|db\.|pool\.|tx\.)\b', context, re.IGNORECASE)
            if not sql_kw and not db_call:
                return False, f"SQL injection finding rejected: code at line {finding.line} contains no SQL or database operations."
            # Check for parameterized queries in other languages
            if re.search(r'\.query\(\s*["\'][^"\']*\$(?:1|\?)[^"\']*["\']\s*,\s*\[', context):
                return False, f"SQL injection finding rejected: query uses safe parameterized placeholders."

    # 2. ZeroDivisionError Verification
    if "zerodivision" in claim_text or "division by zero" in claim_text or "divide by zero" in claim_text:
        if is_python:
            target_node = fn_node
            if target_node is None and actual_code:
                try:
                    target_node = ast.parse(actual_code)
                except Exception:
                    pass
            if target_node is not None:
                div_nodes = [n for n in ast.walk(target_node) if isinstance(n, (ast.Div, ast.FloorDiv, ast.Mod))]
                if not div_nodes:
                    return False, f"ZeroDivisionError finding rejected: code at line {finding.line} does not contain division or modulus operations."
                all_div_safe = True
                for parent in ast.walk(target_node):
                    if isinstance(parent, ast.BinOp) and isinstance(parent.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                        if isinstance(parent.right, ast.Constant) and isinstance(parent.right.value, (int, float)) and parent.right.value != 0:
                            continue
                        all_div_safe = False
                        break
                if all_div_safe and div_nodes:
                    return False, f"ZeroDivisionError finding rejected: denominator is a non-zero literal constant."
        else:
            context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]) if finding.line else actual_code
            has_division = bool(re.search(r'/(?!/|\*)|\bdiv\b|%', context))
            if not has_division:
                return False, f"ZeroDivisionError finding rejected: code at line {finding.line} does not contain division."
            literal_denom = re.search(r'/\s*([0-9]+(?:\.[0-9]+)?)\b', actual_code)
            if literal_denom and float(literal_denom.group(1)) != 0.0:
                return False, f"ZeroDivisionError finding rejected: denominator is non-zero literal {literal_denom.group(1)}."

    # 3. Dangerous eval/exec Verification
    is_eval_claim = bool(re.search(r'\b(?:eval|exec)\b', title_lower)) or "arbitrary code execution" in title_lower or "code injection" in title_lower
    if is_eval_claim:
        context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]) if finding.line else actual_code
        if "literal_eval" in context and "ast.literal_eval" in context:
            return False, "eval finding rejected: ast.literal_eval is safe."
        if not re.search(r'\b(?:eval|exec)\s*\(', context):
            return False, f"eval finding rejected: no eval/exec call at line {finding.line}."

    # 4. Hardcoded Credential Verification
    is_cred_claim = any(k in title_lower for k in ("hardcoded", "credential", "secret", "api_key")) or any(k in rc_lower for k in ("hardcoded", "credential", "secret", "api_key"))
    if is_cred_claim:
        context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-1, 2)]) if finding.line else actual_code
        if any(env_kw in context for env_kw in ("os.getenv(", "os.environ", "environ.get(", "process.env", "System.getenv", "os.Getenv")):
            return False, f"Hardcoded credential finding rejected: reading from environment variable."

    # 5. Unsafe Pickle Deserialization Verification
    is_pickle_claim = "pickle" in title_lower or "deserialization" in title_lower or "pickle" in rc_lower
    if is_pickle_claim:
        context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]) if finding.line else actual_code
        if not re.search(r'\b(?:pickle|_pickle)\.(?:load|loads)\b', context):
            return False, f"pickle finding rejected: no pickle operations at line {finding.line}."

    # 6. SSRF Verification
    is_ssrf_claim = "ssrf" in title_lower or "server-side request forgery" in title_lower or "ssrf" in rc_lower
    if is_ssrf_claim:
        context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]) if finding.line else actual_code
        if not re.search(r'\b(?:requests|httpx|urllib|fetch|http)\.(?:get|post|put|delete|patch|request)\b', context, re.IGNORECASE):
            return False, f"SSRF finding rejected: no HTTP client request at line {finding.line}."

    # 7. Path Traversal Verification
    is_path_claim = "path traversal" in title_lower or "directory traversal" in title_lower or "path traversal" in rc_lower
    if is_path_claim:
        context = " ".join([lines_in_file.get(finding.line + o, "") for o in range(-2, 3)]) if finding.line else actual_code
        if not re.search(r'\b(?:open|readFile|writeFile|createReadStream|os\.remove|os\.unlink|Path)\b', context):
            return False, f"Path traversal finding rejected: no file operation at line {finding.line}."

    return True, None


def validate_source_evidence(
    finding: Finding,
    diff_files: Optional[List[DiffFile]],
    file_lines: Dict[str, Dict[int, str]],
    file_all_code: Dict[str, str],
    seen_evidence: Optional[Dict[str, Tuple[int, str]]] = None,
) -> Tuple[bool, Optional[Finding], Optional[str]]:
    """
    Strictly validates finding against actual source code and diff.
    Verifies:
    1. Source context is available (fails closed if diff_files is empty/missing).
    2. Referenced file matches exact repo-relative path, rejecting ambiguous basename matches.
    3. Reported line number exists in file.
    4. Evidence corresponds to the actual reported source location (+/- 2 lines).
       NEVER falls back to searching full_code when line is specified.
    5. Rejects evidence duplicated from unrelated functions (>3 lines away).
    6. Rejects false ZeroDivision claims where no division operator exists or denominator cannot be zero.
    7. Rejects false SQL injection where function contains no SQL or query is parameterized.
    8. Rejects false eval on ast.literal_eval.
    9. Rejects false credential on os.getenv / environment lookup.
    """
    if not diff_files:
        # Fail closed: never mark evidence as verified when source context is missing
        return False, None, "Source context unavailable: no diff files provided."

    # Step 1: Match file in diff using exact normalized path, rejecting ambiguous basenames
    norm_finding_file = os.path.normpath(finding.file).lstrip("./")
    matched_file_key = None

    # Step 1a: Exact normalized repo-relative path match
    for df_key in file_lines.keys():
        if os.path.normpath(df_key).lstrip("./") == norm_finding_file:
            matched_file_key = df_key
            break

    # Step 1b: Disambiguated basename matching
    if not matched_file_key:
        finding_file_base = os.path.basename(finding.file)
        basename_matches = [
            df_key for df_key in file_lines.keys()
            if os.path.basename(df_key) == finding_file_base
        ]
        if len(basename_matches) == 1:
            matched_file_key = basename_matches[0]
        elif len(basename_matches) > 1:
            return False, None, f"Ambiguous file reference: multiple files in diff match basename '{finding_file_base}': {basename_matches}"
        else:
            return False, None, f"Referenced file '{finding.file}' does not exist in the submitted diff."

    # Normalize file path in finding to match diff
    finding.file = matched_file_key
    lines_in_file = file_lines[matched_file_key]
    full_code = file_all_code.get(matched_file_key, "")

    # Step 2: Line number verification
    if finding.line is not None:
        if finding.line not in lines_in_file:
            # Check if evidence matches a nearby line (+/- 2 lines)
            if finding.evidence and finding.evidence.strip():
                norm_ev = normalize_code(finding.evidence)
                matched_line = None
                for offset in (-2, -1, 1, 2):
                    candidate = finding.line + offset
                    if candidate in lines_in_file:
                        cand_norm = normalize_code(lines_in_file[candidate])
                        if cand_norm and len(cand_norm) >= 4 and (norm_ev in cand_norm or cand_norm in norm_ev):
                            matched_line = candidate
                            break
                if matched_line:
                    finding.line = matched_line
                else:
                    return False, None, f"Line {finding.line} does not exist in '{finding.file}' and evidence cannot be verified."
            else:
                return False, None, f"Line {finding.line} does not exist in '{finding.file}'."
    else:
        # If line is None, try to anchor to evidence
        if finding.evidence and finding.evidence.strip():
            norm_ev = normalize_code(finding.evidence)
            for l_num, l_content in lines_in_file.items():
                l_norm = normalize_code(l_content)
                if l_norm and len(l_norm) >= 4 and (norm_ev in l_norm or l_norm in norm_ev):
                    finding.line = l_num
                    break

    # Step 3: Evidence verification against actual code at reported line
    actual_code = lines_in_file.get(finding.line, "") if finding.line else ""
    if finding.evidence and finding.evidence.strip():
        norm_ev = normalize_code(finding.evidence)
        norm_actual = normalize_code(actual_code)

        # Check if actual line matches; if not, check surrounding +/- 2 lines
        if not norm_actual or (norm_ev not in norm_actual and norm_actual not in norm_ev):
            nearby_match = False
            if finding.line:
                for offset in (-2, -1, 1, 2):
                    adj_code = lines_in_file.get(finding.line + offset, "")
                    norm_adj = normalize_code(adj_code)
                    if norm_adj and len(norm_adj) >= 4 and (norm_ev in norm_adj or norm_adj in norm_ev):
                        finding.line = finding.line + offset
                        actual_code = adj_code
                        nearby_match = True
                        break
            if not nearby_match:
                # Evidence does not match reported line or immediate context (+/- 2 lines).
                # NEVER fallback to searching full_code! Reject immediately!
                return False, None, f"Evidence '{finding.evidence.strip()}' does not match line {finding.line} in '{finding.file}'."
    elif actual_code:
        # Populate actual evidence from source code (never invent fake code)
        finding.evidence = actual_code.strip()

    # Step 4: Prevent evidence theft / duplication across unrelated functions
    if seen_evidence is not None and finding.evidence and finding.line is not None:
        norm_ev = normalize_code(finding.evidence)
        if len(norm_ev) >= 20:
            if norm_ev in seen_evidence:
                prior_line, prior_id = seen_evidence[norm_ev]
                if abs(finding.line - prior_line) > 3:
                    return False, None, f"Finding rejected: evidence is duplicated from line {prior_line} in an unrelated function."
            else:
                seen_evidence[norm_ev] = (finding.line, finding.id or "")

    # Step 5: Semantic sanity checks on specific vulnerability claims
    claim_valid, claim_reason = _verify_vulnerability_claim(
        finding, actual_code, lines_in_file, full_code, matched_file_key
    )
    if not claim_valid:
        return False, None, claim_reason

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
    seen_evidence: Dict[str, Tuple[int, str]] = {}

    for f in raw_findings:
        # Step A: Validate finding against source code and diff
        if diff_files is not None:
            valid, validated_f, reject_reason = validate_source_evidence(
                f, diff_files, file_lines, file_all_code, seen_evidence=seen_evidence
            )
            if not valid or validated_f is None:
                unverified_count += 1
                continue
            f = validated_f
        elif not diff_files:
            # If diff_files is explicitly an empty list, fail closed
            if isinstance(diff_files, list) and len(diff_files) == 0:
                unverified_count += 1
                continue
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
