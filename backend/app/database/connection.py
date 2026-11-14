import aiosqlite
from app.config import settings


async def init_db():
    """Initializes SQLite schema for review storage."""
    async with aiosqlite.connect(settings.database_url) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT,
                summary TEXT,
                findings_count INTEGER DEFAULT 0,
                overall_status TEXT,
                risk_level TEXT,
                result_json TEXT,
                diff_content TEXT
            )
            """
        )
        try:
            await db.execute("ALTER TABLE reviews ADD COLUMN diff_content TEXT")
        except Exception:
            pass
        await db.commit()
