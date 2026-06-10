import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    open_webui_url: str = os.getenv("OPEN_WEBUI_URL", "http://localhost:8080")
    open_webui_api_key: str = os.getenv("OPEN_WEBUI_API_KEY", "")
    model_name: str = os.getenv("MODEL_NAME", "gpt-oss:20b")
    max_input_chars: int = int(os.getenv("MAX_INPUT_CHARS", "12000"))
    report_db_path: str = os.getenv("REPORT_DB_PATH", "backend/data/reports.db")
    seed_dataset_path: str = os.getenv("SEED_DATASET_PATH", "")
    cors_allow_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
        if origin.strip()
    )


settings = Settings()
