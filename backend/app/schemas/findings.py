import hashlib
import re
from typing import Optional, List, Literal, Any
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
    reproduction_scenario: Optional[str] = None
    fix_verification_status: Literal["validated_syntax", "passed_tests", "proposed", "rejected"] = "proposed"

    @model_validator(mode="before")
    @classmethod
    def sanitize_input(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # 1. Normalize Category
        cat = str(data.get("category", "bug")).lower().strip()
        cat_map = {
            "bug": "bug", "bugs": "bug", "defect": "bug", "error": "bug", "logic": "bug", "syntax": "bug",
            "security": "security", "vuln": "security", "vulnerability": "security", "cve": "security", "sec": "security",
            "performance": "performance", "perf": "performance", "speed": "performance", "memory": "performance", "leak": "performance",
            "testing": "testing", "test": "testing", "tests": "testing", "coverage": "testing",
            "style": "style", "quality": "style", "formatting": "style", "lint": "style",
            "maintainability": "maintainability", "refactor": "maintainability", "architecture": "maintainability"
        }
        data["category"] = cat_map.get(cat, "bug")

        # 2. Normalize Severity
        sev = str(data.get("severity", "medium")).lower().strip()
        sev_map = {
            "critical": "critical", "blocker": "critical", "fatal": "critical", "highest": "critical",
            "high": "high", "error": "high", "major": "high",
            "medium": "medium", "warn": "medium", "warning": "medium", "moderate": "medium",
            "low": "low", "info": "low", "minor": "low", "trivial": "low"
        }
        data["severity"] = sev_map.get(sev, "medium")

        # 3. Normalize Line Number
        raw_line = data.get("line")
        if raw_line is not None:
            if isinstance(raw_line, str):
                digits = re.findall(r'\d+', raw_line)
                data["line"] = int(digits[0]) if digits else None
            elif isinstance(raw_line, (int, float)):
                data["line"] = int(raw_line) if int(raw_line) > 0 else None
            else:
                data["line"] = None

        # 4. Normalize Confidence
        raw_conf = data.get("confidence")
        if raw_conf is not None:
            try:
                conf = float(raw_conf)
                if conf > 1.0 and conf <= 100.0:
                    conf = conf / 100.0
                data["confidence"] = max(0.0, min(1.0, conf))
            except (ValueError, TypeError):
                data["confidence"] = 0.85
        else:
            data["confidence"] = 0.85

        # 5. Normalize File
        if not data.get("file"):
            data["file"] = "code.py"

        # 6. Normalize Suggested Fix
        fix = data.get("suggested_fix")
        if fix is not None:
            if not isinstance(fix, str) or not fix.strip():
                data["suggested_fix"] = None

        # 7. Normalize fix verification status
        fvs = str(data.get("fix_verification_status", "proposed")).lower().strip()
        fvs_valid = {"validated_syntax", "passed_tests", "proposed", "rejected"}
        data["fix_verification_status"] = fvs if fvs in fvs_valid else "proposed"

        # 8. Fallbacks for required text fields
        data.setdefault("title", "Detected Code Issue")
        data.setdefault("description", "Potential code issue identified in change.")
        data.setdefault("impact", "May cause unexpected behavior or failure in execution.")
        data.setdefault("recommendation", "Review and correct the identified logic.")

        return data

    @model_validator(mode="after")
    def populate_defaults(self):
        if not self.id:
            self.id = _generate_finding_id(self.file, self.line, self.category, self.title)
        if not self.root_cause and self.description:
            # First sentence as fallback root cause
            self.root_cause = self.description.split(".")[0].strip()
        if not self.reproduction_scenario and self.impact:
            self.reproduction_scenario = self.impact
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
    partial_analysis: bool = False
    unverified_findings_count: int = 0

    @model_validator(mode="before")
    @classmethod
    def sanitize_result(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        # Normalize overall_status
        status = str(data.get("overall_status", "changes_requested")).lower().strip().replace(" ", "_").replace("-", "_")
        status_map = {
            "approved": "approved", "pass": "approved", "passed": "approved", "ok": "approved",
            "changes_requested": "changes_requested", "rejected": "changes_requested", "fail": "changes_requested", "failed": "changes_requested",
            "needs_attention": "needs_attention", "warning": "needs_attention", "attention": "needs_attention"
        }
        data["overall_status"] = status_map.get(status, "changes_requested")

        # Normalize risk_level
        risk = str(data.get("risk_level", "medium")).lower().strip()
        risk_map = {
            "critical": "critical", "high": "high", "medium": "medium", "low": "low"
        }
        data["risk_level"] = risk_map.get(risk, "medium")

        # Fallback for files_reviewed
        if not isinstance(data.get("files_reviewed"), int):
            data["files_reviewed"] = 1

        # Fallback for summary
        if not data.get("summary"):
            data["summary"] = "Code review completed."

        return data
