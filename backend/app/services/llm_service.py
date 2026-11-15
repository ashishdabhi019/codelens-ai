import httpx
import json
import re
from app.config import settings
from app.schemas.findings import ReviewResult

REVIEW_PROMPT_TEMPLATE = """You are an expert senior code reviewer. Perform a comprehensive, deep code review of the changed code.

CRITICAL INSTRUCTIONS:
- Identify ALL logical bugs, incorrect mathematical calculations, division-by-zero errors, missing input validation, incorrect business logic, and security vulnerabilities across ANY programming language.
- UNIVERSAL MULTI-LANGUAGE PROFICIENCY:
  * Review code in any language (Python, TypeScript, JavaScript, Go, Java, C/C++, Rust, PHP, C#, Ruby, SQL).
  * Apply language-specific security and correctness standards:
    - JavaScript/TypeScript: DOM XSS (e.g. innerHTML), template literal SQL injection, unhandled promise rejections, sort() without comparator, prototype pollution.
    - Go: Unchecked error returns, nil pointer dereferences, goroutine/channel leaks, race conditions.
    - Java: Resource leaks (missing try-with-resources), SQL string concatenation, NullPointerExceptions.
    - C/C++: Buffer overflows (strcpy, sprintf, gets), memory leaks, pointer mismanagement, integer overflows.
    - Python: ZeroDivisionError, mutable default arguments, f-string SQLi, command injection, resource leaks.
- REVIEW RESULTING CODE, NOT SOLVED BUGS IN DELETED LINES:
  * In git diffs, lines marked with '-' are DELETED OLD CODE.
  * If the developer fixed an old bug by deleting a '-' line and replacing it with a '+' line (for example, replacing subtotal addition with multiplication), DO NOT report it as an active bug! It is already fixed by the author.
  * ONLY report bugs that remain unresolved in the resulting new code ('+' added or unchanged lines).
- MATHEMATICAL ACCURACY & ZERO DIVISION:
  * Average is always calculated as sum divided by count. NEVER claim an average should be calculated using multiplication.
  * ZERO DIVISION: ONLY report ZeroDivisionError when the code explicitly performs division or modulus ('/', '//', '%') where the divisor can evaluate to zero. NEVER claim multiplication (e.g. `total_spend * 0.125`) is division or causes ZeroDivisionError.
- SQL INJECTION STRICTNESS:
  * ONLY report SQL Injection if the code explicitly executes or constructs dynamic SQL queries with unparameterized variables (f-strings, string concatenation, or .format()).
  * NEVER report SQL Injection on a function that contains NO database operations or NO SQL queries (e.g. pure math functions, discount calculators, average calculations, pickle loaders, eval functions, image downloaders, webhook callers, or password hashers).
  * NEVER report SQL Injection on safe parameterized queries (e.g. `cursor.execute("... WHERE id = ?", (param,))`).
  * NEVER copy an SQL query or evidence line from an earlier function to a different function.
  * Evidence MUST be verbatim from the exact function being reviewed.
- VERBATIM EVIDENCE & LOCAL ANCHORING:
  * In "evidence", copy the EXACT line from the submitted code where the issue resides. Never invent code, variables, or lines.
  * Specify the EXACT 1-based line number corresponding to that evidence.
- For EVERY issue found:
  * Specify the EXACT 1-based line number in the submitted code where the issue occurs.
  * Identify the exact root cause of the fault.
  * Extract the exact evidence line from the submitted code.
  * Provide a clear explanation of what is wrong and why.
  * Provide a concrete failure mode or impact scenario (e.g. "Calling calculate_average([]) crashes with ZeroDivisionError").
  * In "suggested_fix", provide the EXACT corrected code snippet that actually fixes the bug. NEVER return the original buggy code.
- AVOID UNSUPPORTED ASSUMPTIONS: Do NOT invent business requirements or arbitrary numbers (e.g., do not assume a premium discount should be 10%). If business logic seems uncertain or contradictory, report it as a potential logic discrepancy and explain what requirement needs confirmation. Leave suggested_fix as null if business rules are unconfirmed.
- ACCURATE SUMMARY & TESTS: NEVER claim unit tests exist unless test functions (e.g. `test_...`, `assert`) are explicitly present in the submitted code. Distinguish missing test coverage clearly.
- Focus: {focus}
- Language: {language}

Submitted code changes:
{code_sections}

{additional_instructions}

Respond strictly with valid JSON conforming to this schema:
{{
  "summary": "Concise 2-3 sentence overview of change quality, logical errors, and risks",
  "overall_status": "approved | changes_requested | needs_attention",
  "risk_level": "low | medium | high | critical",
  "files_reviewed": <int>,
  "findings": [
    {{
      "title": "Short descriptive title",
      "category": "bug | security | performance | testing | style | maintainability",
      "severity": "critical | high | medium | low",
      "file": "filename.py",
      "line": <int>,
      "root_cause": "Underlying defect or root cause",
      "evidence": "Exact code line containing the bug",
      "description": "Clear explanation of the problem and why it fails",
      "impact": "Concrete failure mode, crash scenario, or security risk",
      "recommendation": "Prescriptive remediation step",
      "suggested_fix": "Exact replacement code snippet or null",
      "confidence": 0.9
    }}
  ],
  "missing_tests": ["Edge cases or test conditions omitted (e.g. empty inputs, negative numbers)"],
  "positive_observations": ["Well-implemented patterns if any"]
}}"""


async def get_effective_model() -> str:
    """Finds the best available model on local Ollama, falling back gracefully to any installed model."""
    try:
        async with httpx.AsyncClient(timeout=4) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                available = [m.get("name", "") for m in resp.json().get("models", [])]
                # Priority 1: qwen2.5-coder:3b (fastest, high-precision code review model)
                for name in available:
                    if "qwen2.5-coder" in name:
                        return name
                # Priority 2: Configured model
                for name in available:
                    if settings.ollama_model in name or name in settings.ollama_model:
                        return name
                # Priority 3: Any available local model (e.g. deepseek-r1:8b, llama3.2)
                if available:
                    return available[0]
    except Exception:
        pass
    return settings.ollama_model


async def call_ollama(prompt: str) -> str:
    """Calls local Ollama generation endpoint with JSON grammar enforcement."""
    model_name = await get_effective_model()
    async with httpx.AsyncClient(timeout=settings.review_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ollama_base_url}/api/generate",
            json={
                "model": model_name,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                },
            },
        )
        response.raise_for_status()
        return response.json()["response"]


def extract_json(text: str) -> dict:
    """Extracts JSON object from raw response text, handling fences and whitespace."""
    cleaned = text.strip()

    # Pass 1: Try direct parse (fast path when the model obeys formatting instructions)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Pass 2: Extract from markdown code fences (```json ... ```)
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    # Pass 3: Greedy search for the outermost {...} curly braces if the model included conversational preamble
    brace_match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(1))
        except json.JSONDecodeError:
            pass

    raise ValueError("Failed to extract valid JSON from model output")


async def generate_review(
    code_sections: dict,
    focus: str = "all",
    language: str = "auto-detect",
    additional_instructions: str = "",
    files_reviewed: int = 1,
) -> tuple[ReviewResult, bool]:
    """Queries configured LLM for semantic review, falling back gracefully if offline."""
    prompt = REVIEW_PROMPT_TEMPLATE.format(
        focus=focus,
        language=language or "auto-detect",
        code_sections="\n\n".join(f"File: {k}\n{v}" for k, v in code_sections.items()),
        additional_instructions=(
            f"Additional guidelines: {additional_instructions}" if additional_instructions else ""
        ),
    )

    for attempt in range(settings.max_retries):
        try:
            raw = await call_ollama(prompt)
            data = extract_json(raw)
            for f in data.get("findings", []):
                # Baseline confidence for LLM probabilistic findings
                f.setdefault("confidence", 0.85)
            data["files_reviewed"] = files_reviewed
            data["llm_available"] = True
            data["partial_analysis"] = False
            data.setdefault("deterministic_findings", [])
            return ReviewResult(**data), True
        except (httpx.ConnectError, httpx.TimeoutException):
            # Ollama service is not running locally or timed out; don't retry in a loop, fail-fast to deterministic
            break
        except Exception:
            if attempt == settings.max_retries - 1:
                break

    # Graceful degradation: return partial analysis result so the user gets full deterministic rule results
    return ReviewResult(
        summary="Static inspection complete. LLM semantic analysis was offline (partial review).",
        overall_status="needs_attention",
        risk_level="medium",
        files_reviewed=files_reviewed,
        findings=[],
        missing_tests=[],
        positive_observations=[],
        llm_available=False,
        partial_analysis=True,
    ), False
