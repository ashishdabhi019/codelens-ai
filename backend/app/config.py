from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    llm_provider: str = "ollama"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder:3b"
    max_diff_size_bytes: int = 500_000
    max_retries: int = 3
    review_timeout_seconds: int = 120
    database_url: str = "codelens.db"
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]


settings = Settings()
