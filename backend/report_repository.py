import json
import sqlite3
from pathlib import Path
from typing import Any


class ReportRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    content_type TEXT,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    model TEXT NOT NULL,
                    text_char_count INTEGER NOT NULL,
                    truncated INTEGER NOT NULL,
                    cti_json TEXT NOT NULL,
                    validation_json TEXT NOT NULL,
                    raw_model_output TEXT,
                    cleaned_output TEXT
                )
                """
            )
            connection.commit()

    def save(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO reports (
                    id,
                    filename,
                    content_type,
                    size_bytes,
                    created_at,
                    model,
                    text_char_count,
                    truncated,
                    cti_json,
                    validation_json,
                    raw_model_output,
                    cleaned_output
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    record["filename"],
                    record.get("content_type"),
                    record["size_bytes"],
                    record["created_at"],
                    record["model"],
                    record["text_char_count"],
                    int(record["truncated"]),
                    json.dumps(record["cti"], ensure_ascii=False),
                    json.dumps(record["validation"], ensure_ascii=False),
                    record.get("raw_model_output"),
                    record.get("cleaned_output"),
                ),
            )
            connection.commit()

        return record

    def list_reports(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM reports
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._row_to_record(row, include_outputs=False) for row in rows]

    def get(self, report_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM reports
                WHERE id = ?
                """,
                (report_id,),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_record(row, include_outputs=True)

    def _row_to_record(self, row: sqlite3.Row, include_outputs: bool) -> dict[str, Any]:
        cti = json.loads(row["cti_json"])
        validation = json.loads(row["validation_json"])
        record: dict[str, Any] = {
            "id": row["id"],
            "filename": row["filename"],
            "content_type": row["content_type"],
            "size_bytes": row["size_bytes"],
            "created_at": row["created_at"],
            "model": row["model"],
            "text_char_count": row["text_char_count"],
            "truncated": bool(row["truncated"]),
            "summary": cti.get("threat_summary", {}),
            "counts": build_counts(cti),
            "cti": cti,
            "validation": validation,
        }

        if include_outputs:
            record["raw_model_output"] = row["raw_model_output"]
            record["cleaned_output"] = row["cleaned_output"]

        return record


def build_counts(cti: dict[str, Any]) -> dict[str, int]:
    return {
        "indicators": _list_count(cti.get("indicators")),
        "malware_or_tools": _list_count(cti.get("malware_or_tools")),
        "threat_actors": _list_count(cti.get("threat_actors")),
        "attack_behaviors": _list_count(cti.get("attack_behaviors")),
        "attack_mapping": _list_count(cti.get("attack_mapping")),
        "defensive_recommendations": _list_count(cti.get("defensive_recommendations")),
    }


def _list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0
