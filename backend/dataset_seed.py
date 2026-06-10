import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report_processor import REQUIRED_TOP_LEVEL_FIELDS, validate_cti_json
from .report_repository import ReportRepository


def seed_reports_from_dataset(
    repository: ReportRepository,
    dataset_path: str,
    model_name: str,
) -> dict[str, Any]:
    if not dataset_path:
        return {"enabled": False, "inserted": 0, "skipped": 0, "path": ""}

    path = Path(dataset_path)

    if not path.exists():
        return {"enabled": True, "inserted": 0, "skipped": 0, "path": str(path)}

    payload = json.loads(path.read_text(encoding="utf-8"))
    items = _extract_dataset_items(payload)
    inserted = 0
    skipped = 0

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue

        record = _dataset_item_to_report_record(item, index, path.name, model_name)

        if repository.save_if_missing(record):
            inserted += 1
        else:
            skipped += 1

    return {
        "enabled": True,
        "inserted": inserted,
        "skipped": skipped,
        "path": str(path),
    }


def _extract_dataset_items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        for key in ("reports", "data", "items", "records", "samples"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return [payload]

    return []


def _dataset_item_to_report_record(
    item: dict[str, Any],
    index: int,
    dataset_name: str,
    model_name: str,
) -> dict[str, Any]:
    cti = _extract_cti(item)
    serialized = json.dumps(item, ensure_ascii=False, sort_keys=True)
    fallback_id = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

    report_id = str(
        item.get("id")
        or item.get("report_id")
        or item.get("uuid")
        or f"seed-{fallback_id}"
    )
    filename = str(
        item.get("filename")
        or item.get("file_name")
        or item.get("title")
        or item.get("name")
        or f"{dataset_name}#{index + 1}"
    )
    created_at = str(
        item.get("created_at")
        or item.get("createdAt")
        or item.get("date")
        or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    raw_text = item.get("text") or item.get("report_text") or item.get("content") or ""

    return {
        "id": report_id,
        "filename": filename,
        "content_type": "application/json",
        "size_bytes": len(serialized.encode("utf-8")),
        "created_at": created_at,
        "model": str(item.get("model") or model_name or "seed-dataset"),
        "text_char_count": len(str(raw_text)),
        "truncated": False,
        "cti": cti,
        "validation": validate_cti_json(cti),
        "raw_model_output": json.dumps(item, ensure_ascii=False),
        "cleaned_output": json.dumps(cti, ensure_ascii=False),
    }


def _extract_cti(item: dict[str, Any]) -> dict[str, Any]:
    for key in ("cti", "cti_json", "extraction", "result", "output"):
        value = item.get(key)
        if isinstance(value, dict):
            return _ensure_cti_shape(value)

    if "summary" in item or "iocs" in item or "ttps" in item:
        return _ensure_cti_shape(
            {
                "threat_summary": {
                    "main_threat": item.get("summary") or "",
                    "target_platform": item.get("target_platform") or "",
                    "target_sector": item.get("target_sector") or "",
                    "attack_goal": item.get("attack_goal") or "",
                    "confidence": item.get("confidence") or 1.0,
                },
                "indicators": [
                    {
                        "type": indicator.get("type", ""),
                        "value": indicator.get("value", ""),
                        "role": indicator.get("role", ""),
                        "evidence": indicator.get("evidence", item.get("summary", "")),
                        "confidence": indicator.get("confidence", 1.0),
                    }
                    for indicator in _list_of_dicts(item.get("iocs"))
                ],
                "attack_mapping": [
                    {
                        "tactic": mapping.get("tactic", ""),
                        "technique": mapping.get("technique", ""),
                        "mitre_id": mapping.get("mitre_id", ""),
                        "evidence": mapping.get("evidence", item.get("summary", "")),
                        "confidence": mapping.get("confidence", 1.0),
                    }
                    for mapping in _list_of_dicts(item.get("ttps"))
                ],
            }
        )

    if any(field in item for field in REQUIRED_TOP_LEVEL_FIELDS):
        return _ensure_cti_shape(item)

    return _ensure_cti_shape(
        {
            "threat_summary": {
                "main_threat": item.get("title") or item.get("name") or "",
                "target_platform": item.get("target_platform") or "",
                "target_sector": item.get("target_sector") or "",
                "attack_goal": item.get("attack_goal") or "",
                "confidence": item.get("confidence") or 0.0,
            },
            "source_metadata": item,
        }
    )


def _ensure_cti_shape(cti: dict[str, Any]) -> dict[str, Any]:
    shaped = dict(cti)
    shaped.setdefault(
        "threat_summary",
        {
            "main_threat": "",
            "target_platform": "",
            "target_sector": "",
            "attack_goal": "",
            "confidence": 0.0,
        },
    )

    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field == "threat_summary":
            continue
        shaped.setdefault(field, [])

    return shaped


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [item for item in value if isinstance(item, dict)]
