import httpx
import json
import re
from app.config import settings
from app.schemas.findings import ReviewResult

REVIEW_PROMPT_TEMPLATE = """You are a senior code reviewer. Analyze the following Git diff and provide a structured code review.

RULES:
- Only report findings that are directly grounded in the submitted code changes
- Do not invent or assume issues not visible in the diff
- Be specific about file names and line numbers
- Focus on: {focus}

Language: {language}

Code changes:
{code_sections}

{additional_instructions}

Respond strictly with valid JSON conforming to this schema:
{{
  "summary": "Concise 2-3 sentence overview of the change quality and risks",
  "overall_status": "approved | changes_requested | needs_attention",
  "risk_level": "low | medium | high | critical",
  "files_reviewed": <int>,
  "findings": [
    {{
      "title": "Short descriptive title",
      "category": "bug | security | performance | testing | style | maintainability",
      "severity": "critical | high | medium | low",
      "file": "filename.py",
      "line": <line_number_or_null>,
      "description": "Clear explanation of the problem",
      "impact": "Concrete failure mode or security risk",
      "recommendation": "Prescriptive remediation step",
      "suggested_fix": "Corrected code snippet or null",
      "confidence": 0.8
    }}
  ],
  "missing_tests": ["Edge cases or test conditions omitted"],
  "positive_observations": ["Well-implemented patterns in the diff"]
}}"""


async def call_ollama(prompt: str) -> str:
    """Calls local Ollama generation endpoint."""
    async with httpx.AsyncClient(timeout=settings.review_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ollama_base_url}/api/generate",
            json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
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
            data.setdefault("deterministic_findings", [])
            return ReviewResult(**data), True
        except (httpx.ConnectError, httpx.TimeoutException):
            # Ollama service is not running locally; don't retry in a loop, fail-fast to deterministic
            break
        except Exception:
            if attempt == settings.max_retries - 1:
                break

    # Graceful degradation: return a clean baseline so the user still gets full deterministic rule results
    return ReviewResult(
        summary="Deterministic inspection complete. LLM semantic analysis was offline.",
        overall_status="approved",
        risk_level="low",
        files_reviewed=files_reviewed,
        findings=[],
        missing_tests=[],
        positive_observations=[],
        llm_available=False,
    ), False
