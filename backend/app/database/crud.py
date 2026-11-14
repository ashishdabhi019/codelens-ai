import aiosqlite
from app.config import settings


async def save_review(
    id: str,
    created_at: str,
    filename: str,
    summary: str,
    findings_count: int,
    overall_status: str,
    risk_level: str,
    result_json: str,
    diff_content: str = "",
):
    async with aiosqlite.connect(settings.database_url) as db:
        await db.execute(
            "INSERT INTO reviews VALUES (?,?,?,?,?,?,?,?,?)",
            (id, created_at, filename, summary, findings_count, overall_status, risk_level, result_json, diff_content),
        )
        await db.commit()


async def list_reviews():
    async with aiosqlite.connect(settings.database_url) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, created_at, filename, summary, findings_count, overall_status, risk_level "
            "FROM reviews ORDER BY created_at DESC"
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]


async def get_review(id: str):
    async with aiosqlite.connect(settings.database_url) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM reviews WHERE id=?", (id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None


async def delete_review(id: str):
    async with aiosqlite.connect(settings.database_url) as db:
        await db.execute("DELETE FROM reviews WHERE id=?", (id,))
        await db.commit()
