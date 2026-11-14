import uuid
import json
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from app.schemas.findings import ReviewResult
from app.schemas.review import ReviewRequest, ReviewResponse, ReviewHistoryItem
from app.agents.code_review_agent import run_review
from app.database import crud
from app.config import settings

router = APIRouter()


@router.post("", response_model=ReviewResponse)
async def create_review(request: ReviewRequest):
    # Measure end-to-end processing latency for performance tracking
    start = time.perf_counter()
    try:
        result = await run_review(request)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Review execution error: {str(e)}")

    review_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    elapsed = time.perf_counter() - start

    # Persist the review and raw diff content so the frontend can render the Devin AI-style inline review
    await crud.save_review(
        id=review_id,
        created_at=created_at,
        filename=request.filename or "stdin.diff",
        summary=result.summary,
        findings_count=len(result.findings),
        overall_status=result.overall_status,
        risk_level=result.risk_level,
        result_json=result.model_dump_json(),
        diff_content=request.diff_content,
    )

    return ReviewResponse(
        id=review_id,
        created_at=datetime.fromisoformat(created_at),
        result=result,
        processing_time_seconds=round(elapsed, 2),
        diff_content=request.diff_content,
        filename=request.filename or "stdin.diff",
    )


SUPPORTED_EXTENSIONS = (
    ".diff", ".patch", ".py", ".js", ".ts", ".tsx", ".jsx",
    ".go", ".rs", ".java", ".cpp", ".c", ".h", ".hpp", ".cs",
    ".rb", ".php", ".swift", ".kt", ".sql", ".sh", ".txt",
)


def ensure_unified_diff(content: str, filename: str = "code.py") -> str:
    """If content is raw source code rather than a unified diff, wrap it as a new-file diff."""
    if "--- " in content and "+++ " in content and "@@" in content:
        return content
    lines = content.splitlines()
    header = [
        f"diff --git a/{filename} b/{filename}",
        "new file mode 100644",
        "--- /dev/null",
        f"+++ b/{filename}",
        f"@@ -0,0 +1,{max(1, len(lines))} @@",
    ]
    diff_lines = [f"+{l}" for l in lines]
    return "\n".join(header + diff_lines) + "\n"


@router.post("/upload", response_model=ReviewResponse)
async def upload_review(
    file: UploadFile = File(...),
    focus: str = Form("all"),
    language: Optional[str] = Form(None),
    additional_instructions: Optional[str] = Form(None),
):
    filename = file.filename or "code.py"
    if not filename.lower().endswith(SUPPORTED_EXTENSIONS):
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported file type. Supported extensions: {', '.join(SUPPORTED_EXTENSIONS)}",
        )

    content = await file.read()
    if len(content) > settings.max_diff_size_bytes:
        raise HTTPException(
            status_code=422,
            detail=f"File exceeds maximum allowed size ({settings.max_diff_size_bytes} bytes)",
        )

    raw_text = content.decode("utf-8", errors="replace")
    formatted_diff = ensure_unified_diff(raw_text, filename)

    request = ReviewRequest(
        diff_content=formatted_diff,
        focus=focus,
        language=language,
        additional_instructions=additional_instructions,
        filename=filename,
    )
    return await create_review(request)


@router.get("", response_model=list[ReviewHistoryItem])
async def get_reviews():
    rows = await crud.list_reviews()
    return [ReviewHistoryItem(**r) for r in rows]


@router.get("/{review_id}", response_model=ReviewResponse)
async def get_review(review_id: str):
    row = await crud.get_review(review_id)
    if not row:
        raise HTTPException(status_code=404, detail="Review not found")

    result_data = json.loads(row["result_json"])
    return ReviewResponse(
        id=row["id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        result=ReviewResult(**result_data),
        processing_time_seconds=0.0,
        diff_content=row["diff_content"] if "diff_content" in row and row["diff_content"] else None,
        filename=row.get("filename") or "code",
    )


@router.delete("/{review_id}")
async def delete_review(review_id: str):
    await crud.delete_review(review_id)
    return {"deleted": True}
