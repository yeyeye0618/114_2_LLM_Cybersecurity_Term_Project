from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .report_processor import (
    ConfigurationError,
    ModelOutputError,
    UpstreamModelError,
    UnsupportedFileError,
    analyze_report_content,
)
from .report_repository import ReportRepository, build_counts


app = FastAPI(title="CTI Report Backend")
repository = ReportRepository(settings.report_db_path)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_allow_origins) or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    message = exc.detail.get("message") if isinstance(exc.detail, dict) else str(exc.detail)
    return JSONResponse(status_code=exc.status_code, content={"message": message})


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/reports/analyze")
async def analyze_report(file: UploadFile = File(...)) -> JSONResponse:
    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail={"message": "Uploaded file is empty."})

    filename = file.filename or "uploaded-report"

    try:
        analysis = analyze_report_content(settings, filename, content)
    except UnsupportedFileError as exc:
        raise HTTPException(status_code=400, detail={"message": str(exc)}) from exc
    except ConfigurationError as exc:
        raise HTTPException(status_code=503, detail={"message": str(exc)}) from exc
    except (UpstreamModelError, ModelOutputError) as exc:
        raise HTTPException(status_code=502, detail={"message": str(exc)}) from exc

    record = {
        "id": str(uuid4()),
        "filename": filename,
        "content_type": file.content_type,
        "size_bytes": len(content),
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "model": settings.model_name,
        "text_char_count": analysis["text_char_count"],
        "truncated": analysis["truncated"],
        "cti": analysis["cti"],
        "validation": analysis["validation"],
        "raw_model_output": analysis["raw_model_output"],
        "cleaned_output": analysis["cleaned_output"],
    }
    repository.save(record)
    record["summary"] = record["cti"].get("threat_summary", {})
    record["counts"] = build_counts(record["cti"])

    return JSONResponse(record)


@app.get("/api/reports")
def list_reports() -> list[dict]:
    return repository.list_reports()


@app.get("/api/reports/{report_id}")
def get_report(report_id: str) -> dict:
    record = repository.get(report_id)

    if record is None:
        raise HTTPException(status_code=404, detail={"message": "Report not found."})

    return record
