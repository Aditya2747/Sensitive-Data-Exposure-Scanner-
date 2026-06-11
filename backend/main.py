"""
main.py
-------
FastAPI entrypoint for the Sensitive Data Exposure Scanner.

Exposes a single POST endpoint `/api/scan` that:
  1. Accepts a multipart file upload (.txt, .csv, .pdf, .docx, max 10 MB).
  2. Extracts text via services.extractor.
  3. Scans with services.detector.
  4. Scores and classifies via services.risk_engine.
  5. Returns a fully-validated ScanResponse (schemas.ScanResponse).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from schemas import ErrorResponse, ScanResponse
from services.detector import scan_text
from services.extractor import MAX_BYTES, ExtractionError, extract_text
from services.risk_engine import (
    build_recommendations,
    classify_risk_level,
    compute_risk,
)



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("scanner-api")

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sensitive Data Exposure Scanner",
    version="1.0.0",
    description=(
        "Upload documents (.txt, .csv, .pdf, .docx) and receive a "
        "compliance report with PII/secret detections, a risk score, and "
        "actionable recommendations."
    ),
)

# ---------------------------------------------------------------------------
# CORS – allowlisted origins pulled from env (comma-separated)
# ---------------------------------------------------------------------------

_origins_raw = os.getenv("CORS_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in _origins_raw.split(",") if o.strip()] or ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health() -> Dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Main scan endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/scan",
    response_model=ScanResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Bad Request"},
        413: {"model": ErrorResponse, "description": "Payload Too Large"},
        422: {"model": ErrorResponse, "description": "Unprocessable Entity"},
        500: {"model": ErrorResponse, "description": "Internal Server Error"},
    },
    tags=["scanner"],
    summary="Scan an uploaded document for sensitive data",
)
async def scan_file(file: UploadFile = File(...)) -> ScanResponse:
    """
    Accept a multipart file upload and return a compliance report.
    """
    t0 = time.perf_counter()

    # --- 1. Validate filename & extension ---
    filename = file.filename or ""
    allowed_ext = {"txt", "csv", "pdf", "docx"}
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in allowed_ext:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '.{ext}'. Allowed: {sorted(allowed_ext)}",
        )

    # --- 2. Read bytes with 10 MB hard cap ---
    try:
        data = await file.read()
    except Exception as exc:
        logger.exception("Failed to read upload: %s", filename)
        raise HTTPException(status_code=400, detail=f"Upload read error: {exc}")

    if len(data) > MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File too large ({len(data):,} bytes). "
                f"Maximum allowed size is {MAX_BYTES:,} bytes (10 MB)."
            ),
        )

    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # --- 3. Extract text ---
    try:
        text, size_bytes = extract_text(filename, data)
    except ExtractionError as exc:
        logger.warning("Extraction failed for %s: %s", filename, exc)
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        logger.exception("Unexpected extraction error for %s", filename)
        raise HTTPException(status_code=500, detail="Internal extraction failure.")

    # --- 4. Detect sensitive patterns ---
    findings = scan_text(text)

    # --- 5. Risk scoring + recommendations ---
    score_result = compute_risk(findings)
    recommendations = build_recommendations(findings)

    total_findings = sum(f.get("count", 0) for f in findings)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    logger.info(
        "Scanned %s | size=%d B | chars=%d | findings=%d | score=%d | level=%s | raw=%.2f | bonus=%d | %d ms",
        filename, size_bytes, len(text), total_findings, 
        score_result["score"], score_result["risk_level"],
        score_result["raw_score"], score_result["cooccurrence_bonus"],
        elapsed_ms,
    )

    return ScanResponse(
        status="success",
        filename=filename,
        size_bytes=size_bytes,
        total_characters=len(text),
        score=score_result["score"],
        risk_level=score_result["risk_level"],
        total_findings=total_findings,
        findings=[
            {
                "category": f["category"],
                "label": f["label"],
                "count": f["count"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "samples": f["samples"],
            }
            for f in findings
        ],
        breakdown=score_result["breakdown"],
        cooccurrence_bonus=score_result["cooccurrence_bonus"],
        raw_score=score_result["raw_score"],
        recommendations=recommendations,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):  # type: ignore[no-untyped-def]
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "detail": "An unexpected internal error occurred.",
            "hint": "Please try again or contact support if the issue persists.",
        },
    )
