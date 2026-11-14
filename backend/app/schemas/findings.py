import hashlib
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, model_validator


def _generate_finding_id(file: str, line: Optional[int], category: str, title: str) -> str:
    """Generates a stable, unique finding identifier."""
    raw = f"{file}:{line or 0}:{category}:{title}".encode("utf-8")
    hash_str = hashlib.sha256(raw).hexdigest()[:6].upper()
    cat_prefix = category[:3].upper()
    return f"CL-{cat_prefix}-{hash_str}"


class Finding(BaseModel):
    id: Optional[str] = None
    title: str
    category: Literal["bug", "security", "performance", "testing", "style", "maintainability"]
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: Optional[int] = None
    root_cause: Optional[str] = None
    evidence: Optional[str] = None
    description: str
    impact: str
    recommendation: str
    suggested_fix: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)

    @model_validator(mode="after")
    def populate_defaults(self):
        if not self.id:
            self.id = _generate_finding_id(self.file, self.line, self.category, self.title)
        if not self.root_cause and self.description:
            # First sentence as fallback root cause
            self.root_cause = self.description.split(".")[0].strip()
        return self


class ReviewResult(BaseModel):
    summary: str
    overall_status: Literal["approved", "changes_requested", "needs_attention"]
    risk_level: Literal["low", "medium", "high", "critical"]
    files_reviewed: int
    findings: List[Finding] = []
    missing_tests: List[str] = []
    positive_observations: List[str] = []
    deterministic_findings: List[Finding] = []
    llm_available: bool = True
