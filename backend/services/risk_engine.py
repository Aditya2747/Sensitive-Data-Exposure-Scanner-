"""
services/risk_engine.py
-----------------------
Compliance Risk Scoring engine for Sensitive Data Exposure Scanner.

SCORING ALGORITHM
-----------------
Final Score = min(100, RawScore + CoOccurrenceBonus)
RawScore    = sum of contributions from each detected data type

STEP 1 — SEVERITY WEIGHTS (base points per data type)
  aadhaar_number        → 35
  pan_number            → 30
  passport_number       → 30
  credit_debit_card     → 30
  aws_credentials       → 30
  api_key               → 25
  jwt_token             → 25
  db_connection_string  → 25
  password_secret       → 20
  phone_number          → 15
  email_address         → 10

STEP 2 — CONFIDENCE FACTOR (per match)
  HIGH   → × 1.0
  MEDIUM → × 0.7
  LOW    → × 0.4

STEP 3 — VOLUME MULTIPLIER (per data type)
  count == 0    → × 0
  count == 1    → × 1.0
  count  2–5    → × 1.3
  count  6–20   → × 1.6
  count  21–100 → × 2.0
  count > 100   → × 2.5

STEP 4 — PER-TYPE CONTRIBUTION
  contribution = severity_weight × confidence_factor × volume_multiplier

STEP 5 — CO-OCCURRENCE BONUS
  1 category   → bonus = 0
  2 categories → bonus = 5
  3+ categories → bonus = 12

STEP 6 — FINAL SCORE + RISK LEVEL
  0  – 29  → LOW
  30 – 59  → MEDIUM
  60 – 84  → HIGH
  85 – 100 → CRITICAL
"""
from __future__ import annotations

from typing import Dict, List, TypedDict

# ---------------------------------------------------------------------------
# Severity weights (base points per data type)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, int] = {
    "aadhaar": 35,
    "pan": 30,
    "passport": 30,
    "credit_card": 30,
    "aws_access": 30,
    "aws_secret": 30,
    "api_key": 25,
    "jwt": 25,
    "db_conn": 25,
    "password": 20,
    "phone_in": 15,
    "email": 10,
}

# ---------------------------------------------------------------------------
# Confidence factors
# ---------------------------------------------------------------------------

CONFIDENCE_FACTORS: Dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.7,
    "LOW": 0.4,
}

# ---------------------------------------------------------------------------
# Volume multipliers
# ---------------------------------------------------------------------------

def get_volume_multiplier(count: int) -> float:
    """Return volume multiplier based on instance count."""
    if count == 0:
        return 0.0
    if count == 1:
        return 1.0
    if 2 <= count <= 5:
        return 1.3
    if 6 <= count <= 20:
        return 1.6
    if 21 <= count <= 100:
        return 2.0
    return 2.5

# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------

def classify_risk_level(score: int) -> str:
    """Map final score to risk level."""
    if score <= 29:
        return "LOW"
    if score <= 59:
        return "MEDIUM"
    if score <= 84:
        return "HIGH"
    return "CRITICAL"

# ---------------------------------------------------------------------------
# TypedDict for breakdown entry
# ---------------------------------------------------------------------------

class BreakdownEntry(TypedDict):
    count: int
    confidence: str
    severity_weight: int
    confidence_factor: float
    volume_multiplier: float
    contribution: float


class ScoreResult(TypedDict):
    score: int
    risk_level: str
    breakdown: Dict[str, BreakdownEntry]
    cooccurrence_bonus: int
    raw_score: float
    final_score: int


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------

def compute_risk(detection_input: List[Dict]) -> ScoreResult:
    """
    Compute compliance risk score from detections.

    Parameters
    ----------
    detection_input : list of detection dicts with keys:
        - key: data type key (e.g., "aadhaar", "email")
        - count: number of instances
        - confidence: "HIGH", "MEDIUM", or "LOW"

    Returns
    -------
    ScoreResult with score, risk_level, breakdown, and metadata
    """
    breakdown: Dict[str, BreakdownEntry] = {}
    raw_score = 0.0
    active_categories = 0

    for detection in detection_input:
        key = detection.get("key", "")
        count = int(detection.get("count", 0))
        confidence = detection.get("confidence", "MEDIUM")

        if count == 0:
            continue

        severity_weight = SEVERITY_WEIGHTS.get(key, 10)
        confidence_factor = CONFIDENCE_FACTORS.get(confidence, 0.7)
        volume_multiplier = get_volume_multiplier(count)

        contribution = severity_weight * confidence_factor * volume_multiplier
        contribution = round(contribution, 2)

        breakdown[key] = {
            "count": count,
            "confidence": confidence,
            "severity_weight": severity_weight,
            "confidence_factor": confidence_factor,
            "volume_multiplier": volume_multiplier,
            "contribution": contribution,
        }

        raw_score += contribution
        active_categories += 1

    # Co-occurrence bonus
    if active_categories == 1:
        cooccurrence_bonus = 0
    elif active_categories == 2:
        cooccurrence_bonus = 5
    else:
        cooccurrence_bonus = 12

    final_score = min(100, int(round(raw_score + cooccurrence_bonus)))
    risk_level = classify_risk_level(final_score)

    return {
        "score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "cooccurrence_bonus": cooccurrence_bonus,
        "raw_score": round(raw_score, 2),
        "final_score": final_score,
    }


# ---------------------------------------------------------------------------
# Backward compatibility wrapper
# ---------------------------------------------------------------------------

def compute_risk_legacy(findings: List[Dict]) -> float:
    """Legacy wrapper returning just the score for compatibility."""
    result = compute_risk(findings)
    return float(result["final_score"])


def classify_tier(score: float) -> str:
    """Map a numeric score to a tier label (backward compatible)."""
    return classify_risk_level(int(score))


# ---------------------------------------------------------------------------
# Recommendation mapping
# ---------------------------------------------------------------------------

RECOMMENDATION_MAP: Dict[str, str] = {
    "email": (
        "Email addresses detected – classify dataset as Personally Identifiable "
        "Information (PII) under GDPR / DPDP Act and implement access controls."
    ),
    "phone_in": (
        "Indian phone numbers detected – ensure consent records exist per DPDP "
        "Act 2023 and restrict access to authorised personnel only."
    ),
    "pan": (
        "PAN card numbers found – this is sensitive financial PII under the IT "
        "Act. Encrypt at rest (AES-256) and enable field-level audit logging."
    ),
    "aadhaar": (
        "Aadhaar numbers discovered – UIDAI regulations strictly prohibit "
        "storage of Aadhaar numbers unless absolutely necessary. Anonymize or "
        "tokenize immediately."
    ),
    "passport": (
        "Passport numbers detected – treat as high-sensitivity travel identity "
        "data and notify your DPO (Data Protection Officer)."
    ),
    "credit_card": (
        "Payment card data detected – verify PCI-DSS compliance scope, ensure "
        "PAN is masked, and confirm tokenization is in place."
    ),
    "api_key": (
        "Hard-coded API keys found – rotate credentials immediately via your "
        "provider dashboard and move them to a secrets manager (Vault / AWS "
        "Secrets Manager / environment variables)."
    ),
    "aws_access": (
        "AWS Access Key IDs detected – treat as CRITICAL. Rotate keys NOW, "
        "review CloudTrail for abuse, and enforce IAM least-privilege."
    ),
    "aws_secret": (
        "AWS Secret Access Keys exposed – IMMEDIATELY rotate, invalidate any "
        "active sessions, and audit S3 / resource access for the last 90 days."
    ),
    "jwt": (
        "JWT tokens discovered – revoke the signing key/secret, invalidate "
        "active sessions, and ensure tokens are never logged in plaintext."
    ),
    "password": (
        "Hard-coded passwords/secrets detected – migrate to a secrets vault, "
        "force credential rotation, and implement pre-commit secret scanning."
    ),
    "db_conn": (
        "Database connection strings with embedded credentials found – move "
        "credentials to environment variables or a secrets manager and rotate "
        "database passwords."
    ),
}


def build_recommendations(findings: List[Dict]) -> List[str]:
    """
    Generate actionable compliance recommendations based on the *specific*
    data types that were discovered. Ordered by severity weight.
    """
    # Sort by severity weight descending
    ordered = sorted(
        findings,
        key=lambda f: -SEVERITY_WEIGHTS.get(f.get("key", ""), 0)
    )
    recs: List[str] = []
    seen: set[str] = set()

    for f in ordered:
        key = f.get("key", "")
        if key in RECOMMENDATION_MAP and key not in seen:
            recs.append(RECOMMENDATION_MAP[key])
            seen.add(key)

    # Always-on baseline recommendations
    if findings:
        recs.append(
            "Implement continuous automated secret scanning in CI/CD "
            "pipelines (e.g., GitLeaks, TruffleHog)."
        )
        recs.append(
            "Educate engineering teams on secure handling of PII and "
            "secrets via mandatory security training."
        )

    return recs
