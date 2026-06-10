import json
from io import BytesIO
from typing import Any

import requests
from docx import Document
from pypdf import PdfReader

from .config import Settings
from .prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


REQUIRED_TOP_LEVEL_FIELDS = [
    "threat_summary",
    "indicators",
    "malware_or_tools",
    "threat_actors",
    "attack_behaviors",
    "attack_mapping",
    "defensive_recommendations",
]

TEXT_EXTENSIONS = {".txt", ".md", ".json", ".log"}


class ConfigurationError(RuntimeError):
    pass


class UnsupportedFileError(ValueError):
    pass


class UpstreamModelError(RuntimeError):
    pass


class ModelOutputError(RuntimeError):
    pass


def extract_text_from_txt(content: bytes) -> str:
    return content.decode("utf-8", errors="ignore")


def extract_text_from_docx(content: bytes) -> str:
    doc = Document(BytesIO(content))
    paragraphs = [paragraph.text for paragraph in doc.paragraphs if paragraph.text.strip()]
    return "\n".join(paragraphs)


def extract_text_from_pdf(content: bytes) -> str:
    reader = PdfReader(BytesIO(content))
    texts: list[str] = []

    for page in reader.pages:
        page_text = page.extract_text() or ""
        if page_text.strip():
            texts.append(page_text)

    return "\n".join(texts)


def extract_text(filename: str, content: bytes) -> str:
    lowered = filename.lower()

    if any(lowered.endswith(extension) for extension in TEXT_EXTENSIONS):
        return extract_text_from_txt(content)

    if lowered.endswith(".docx"):
        return extract_text_from_docx(content)

    if lowered.endswith(".pdf"):
        return extract_text_from_pdf(content)

    raise UnsupportedFileError(
        "Unsupported file type. Please upload .txt, .md, .json, .log, .docx, or .pdf"
    )


def call_openwebui(settings: Settings, system_prompt: str, user_prompt: str) -> dict[str, Any]:
    if not settings.open_webui_api_key:
        raise ConfigurationError("OPEN_WEBUI_API_KEY is not set.")

    url = f"{settings.open_webui_url.rstrip('/')}/api/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.open_webui_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": settings.model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=600)
    except requests.RequestException as exc:
        raise UpstreamModelError(f"Open WebUI request failed: {exc}") from exc

    if response.status_code != 200:
        raise UpstreamModelError(
            f"Open WebUI API error {response.status_code}: {response.text}"
        )

    return response.json()


def get_assistant_content(api_response: dict[str, Any]) -> str:
    try:
        content = api_response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        formatted_response = json.dumps(api_response, ensure_ascii=False, indent=2)
        raise UpstreamModelError(
            f"Unexpected Open WebUI API response format: {formatted_response}"
        ) from exc

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = [
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") in {"text", "output_text"}
        ]
        return "\n".join(part for part in text_parts if part)

    raise UpstreamModelError("Unexpected assistant content format from Open WebUI.")


def clean_model_json_output(text: str | None) -> str:
    if text is None:
        return ""

    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned[len("```json") :].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[len("```") :].strip()

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")

    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1].strip()

    return cleaned


def try_parse_json(text: str) -> tuple[dict[str, Any] | None, str | None, str]:
    cleaned = clean_model_json_output(text)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return None, str(exc), cleaned

    if not isinstance(parsed, dict):
        return None, "Model output JSON must be an object.", cleaned

    return parsed, None, cleaned


def validate_cti_json(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "required_fields_present": True,
        "missing_fields": [],
        "confidence_range_valid": True,
        "confidence_errors": [],
    }

    if not isinstance(data, dict):
        result["required_fields_present"] = False
        result["missing_fields"] = REQUIRED_TOP_LEVEL_FIELDS
        return result

    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field not in data:
            result["required_fields_present"] = False
            result["missing_fields"].append(field)

    def walk(obj: Any, path: str = "root") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}"
                if key == "confidence":
                    if not isinstance(value, (int, float)) or not (0.0 <= float(value) <= 1.0):
                        result["confidence_range_valid"] = False
                        result["confidence_errors"].append(
                            {"path": current_path, "value": value}
                        )
                walk(value, current_path)

        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                walk(item, f"{path}[{index}]")

    walk(data)
    return result


def analyze_report_content(
    settings: Settings,
    filename: str,
    content: bytes,
) -> dict[str, Any]:
    report_text = extract_text(filename, content)

    if not report_text.strip():
        raise UnsupportedFileError("No text could be extracted from the uploaded file.")

    truncated_text = report_text[: settings.max_input_chars]
    user_prompt = USER_PROMPT_TEMPLATE.replace("__REPORT_TEXT__", truncated_text)
    api_response = call_openwebui(settings, SYSTEM_PROMPT, user_prompt)
    assistant_output = get_assistant_content(api_response)
    parsed_json, parse_error, cleaned_output = try_parse_json(assistant_output)

    if parsed_json is None:
        raise ModelOutputError(f"Model output is not valid JSON: {parse_error}")

    return {
        "cti": parsed_json,
        "validation": validate_cti_json(parsed_json),
        "raw_model_output": assistant_output,
        "cleaned_output": cleaned_output,
        "text_char_count": len(report_text),
        "truncated": len(report_text) > settings.max_input_chars,
    }
