"""
Pydantic schemas for the Sensitive Data Exposure Scanner API.
Defines robust request/response validation models.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """
    Incoming scan request. The file is transmitted as multipart/form-data.
    This schema is used for documentation and validation of additional metadata.
    """
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream")
    size_bytes: int = Field(default=0, ge=0, le=10 * 1024 * 1024)  # 10 MB cap


# ---------------------------------------------------------------------------
# Finding sub-models
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single category of discovered sensitive data."""
    category: str = Field(..., description="Top-level category: PII or Secrets")
    label: str = Field(..., description="Human-readable label e.g. 'Aadhaar Card'")
    count: int = Field(..., ge=0)
    severity: str = Field(..., description="low | medium | high | critical")
    confidence: str = Field(..., description="HIGH | MEDIUM | LOW")
    samples: List[str] = Field(
        default_factory=list,
        description="Redacted preview snippets (max 3)",
    )


class BreakdownEntry(BaseModel):
    """Detailed scoring breakdown for a data type."""
    count: int = Field(..., ge=0)
    confidence: str = Field(..., description="HIGH | MEDIUM | LOW")
    severity_weight: int = Field(..., ge=0)
    confidence_factor: float = Field(...)
    volume_multiplier: float = Field(...)
    contribution: float = Field(...)


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    """Unified response envelope returned by POST /api/scan."""
    status: str = Field(default="success")
    filename: str
    size_bytes: int = Field(..., ge=0)
    total_characters: int = Field(..., ge=0)
    score: int = Field(..., ge=0, le=100, description="Final compliance risk score")
    risk_level: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    total_findings: int = Field(..., ge=0)
    findings: List[Finding] = Field(default_factory=list)
    breakdown: Dict[str, BreakdownEntry] = Field(default_factory=dict, description="Per-type scoring breakdown")
    cooccurrence_bonus: int = Field(..., ge=0, description="Bonus for multiple data type exposure")
    raw_score: float = Field(..., description="Score before co-occurrence bonus")
    recommendations: List[str] = Field(default_factory=list)
    elapsed_ms: float = Field(..., ge=0.0)

    @field_validator("risk_level")
    @classmethod
    def _validate_tier(cls, v: str) -> str:
        allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if v.upper() not in allowed:
            raise ValueError(f"risk_level must be one of {allowed}")
        return v.upper()


class ErrorResponse(BaseModel):
    """Standardized error envelope."""
    status: str = Field(default="error")
    detail: str
    hint: Optional[str] = None
