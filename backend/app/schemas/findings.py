from pydantic import BaseModel, Field
from typing import Optional, List, Literal


class Finding(BaseModel):
    title: str
    category: Literal["bug", "security", "performance", "testing", "style", "maintainability"]
    severity: Literal["critical", "high", "medium", "low"]
    file: str
    line: Optional[int] = None
    description: str
    impact: str
    recommendation: str
    suggested_fix: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


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
