from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime
from app.schemas.findings import ReviewResult


class ReviewRequest(BaseModel):
    diff_content: str = Field(min_length=1)
    focus: Literal["all", "bugs", "security", "performance", "testing", "style"] = "all"
    language: Optional[str] = None
    additional_instructions: Optional[str] = None
    filename: Optional[str] = None


class ReviewResponse(BaseModel):
    id: str
    created_at: datetime
    result: ReviewResult
    processing_time_seconds: float
    diff_content: Optional[str] = None
    filename: Optional[str] = None


class ReviewHistoryItem(BaseModel):
    id: str
    created_at: str
    filename: Optional[str]
    summary: str
    findings_count: int
    overall_status: str
    risk_level: str
