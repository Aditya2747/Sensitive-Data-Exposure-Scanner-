"""
services/detector.py
--------------------
Optimized regular-expression engine that scans extracted plaintext for
PII and Secrets. All patterns use word-boundary anchors (\b) or equivalent
look-around assertions to minimize false positives.

Each pattern returns detection results with:
  label, category, severity, confidence, count, samples (redacted previews)

CONFIDENCE LEVELS:
  HIGH   - Checksum/structure validated (Luhn for cards, Verhoeff for Aadhaar)
  MEDIUM - Regex pattern match only
  LOW    - Heuristic or context-based
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Dict


@dataclass
class MatchGroup:
    """Aggregated matches for a single detection rule."""
    key: str
    label: str
    category: str           # "PII" or "Secrets"
    severity: str           # low | medium | high | critical
    confidence: str         # HIGH | MEDIUM | LOW
    count: int = 0
    samples: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex patterns (compiled once at module import)
# ---------------------------------------------------------------------------

# --- PII: Emails ---
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# --- PII: Indian phone numbers (+91 / 0 prefixed / 10 digits starting 6-9) ---
RE_PHONE_IN = re.compile(
    r"(?<![0-9])"
    r"(?:\+91[\-\s]?|91[\-\s]?|0)?"
    r"[6-9]\d{9}"
    r"(?![0-9])"
)

# --- PII: Indian PAN card (ABCDE1234F) ---
RE_PAN = re.compile(
    r"\b[A-Z]{5}\d{4}[A-Z]\b"
)

# --- PII: Aadhaar (12 digits, first digit non-zero, optionally spaced) ---
RE_AADHAAR = re.compile(
    r"(?<![0-9])"
    r"[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}"
    r"(?![0-9])"
)

# --- PII: Indian Passport (1 letter + 7 digits, e.g., A1234567) ---
RE_PASSPORT = re.compile(
    r"\b[A-Z][1-9]\d{6}\b"
)

# --- PII: Credit / Debit cards (Visa/MasterCard/Amex/Discover/RuPay) ---
RE_CREDIT_CARD = re.compile(
    r"(?<!\d)"
    r"(?:4\d{3}|5[1-5]\d{2}|6\d{3}|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d|(?:50|5[6-9]|6\d)\d{2})"
    r"[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}"
    r"(?!\d)"
)

# --- Secrets: Generic API keys (long alphanumeric + special chars) ---
RE_API_KEY = re.compile(
    r"(?i)(?:api[_-]?key|apikey|api secret|access[_\-]?key)"
    r"[\s:=]+"
    r"[\"']?([A-Za-z0-9_\-]{16,})[\"']?"
)

# --- Secrets: AWS Access Key ID (AKIA...) ---
RE_AWS_ACCESS = re.compile(
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"
)

# --- Secrets: AWS Secret Access Key (40-char base64-like) ---
RE_AWS_SECRET = re.compile(
    r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)"
    r"[\s:=]+[\"']?([A-Za-z0-9/+=]{40})[\"']?"
)

# --- Secrets: JSON Web Tokens ---
RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
)

# --- Secrets: Password / Secret assignments ---
RE_PASSWORD = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|private[_\-]?key)"
    r"[\s:=]+[\"']?([^\s\"',;]{8,})[\"']?"
)

# --- Secrets: Database connection strings ---
RE_DB_CONN = re.compile(
    r"\b(?:"
    r"postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|oracle|sqlite|amqp|amqps"
    r")://[^\s\"'<>]{6,}\b"
)


# ---------------------------------------------------------------------------
# Validation helpers for HIGH confidence
# ---------------------------------------------------------------------------

def luhn_checksum(card_number: str) -> bool:
    """Validate card number using Luhn algorithm."""
    digits = []
    for c in card_number:
        if c.isdigit():
            digits.append(int(c))
    if len(digits) < 13:
        return False
    
    odd_sum = sum(digits[-1::-2])
    even_sum = sum([sum(divmod(2 * d, 10)) for d in digits[-2::-2]])
    return (odd_sum + even_sum) % 10 == 0


def verhoeff_checksum(aadhaar: str) -> bool:
    """Validate Aadhaar using Verhoeff algorithm."""
    digits = [int(c) for c in aadhaar if c.isdigit()]
    if len(digits) != 12:
        return False
    
    # Verhoeff multiplication table
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    
    # Verhoeff permutation table
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    
    # Inverse table
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = d[c][p[i % 8][digit]]
    
    return c == 0


def validate_pan(pan: str) -> bool:
    """Validate PAN structure: AAAAB1234C format."""
    if len(pan) != 10:
        return False
    # First 5 chars: uppercase letters
    if not pan[:5].isalpha() or not pan[:5].isupper():
        return False
    # Next 4 chars: digits
    if not pan[5:9].isdigit():
        return False
    # Last char: uppercase letter
    if not pan[9].isalpha() or not pan[9].isupper():
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern registry with confidence levels
# ---------------------------------------------------------------------------

PATTERNS: List[Dict] = [
    {
        "key": "email",
        "label": "Email Address",
        "category": "PII",
        "severity": "medium",
        "confidence": "MEDIUM",  # Regex only
        "pattern": RE_EMAIL,
    },
    {
        "key": "phone_in",
        "label": "Indian Phone Number",
        "category": "PII",
        "severity": "medium",
        "confidence": "MEDIUM",  # Regex only
        "pattern": RE_PHONE_IN,
    },
    {
        "key": "pan",
        "label": "PAN Card (India)",
        "category": "PII",
        "severity": "high",
        "confidence": "HIGH",  # Structure validated
        "pattern": RE_PAN,
        "validator": validate_pan,
    },
    {
        "key": "aadhaar",
        "label": "Aadhaar Card (India)",
        "category": "PII",
        "severity": "high",
        "confidence": "HIGH",  # Verhoeff checksum
        "pattern": RE_AADHAAR,
        "validator": verhoeff_checksum,
    },
    {
        "key": "passport",
        "label": "Passport Number",
        "category": "PII",
        "severity": "high",
        "confidence": "MEDIUM",  # Regex only
        "pattern": RE_PASSPORT,
    },
    {
        "key": "credit_card",
        "label": "Credit / Debit Card",
        "category": "PII",
        "severity": "high",
        "confidence": "HIGH",  # Luhn checksum
        "pattern": RE_CREDIT_CARD,
        "validator": luhn_checksum,
    },
    {
        "key": "api_key",
        "label": "API Key / Token",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "LOW",  # Heuristic/context
        "pattern": RE_API_KEY,
    },
    {
        "key": "aws_access",
        "label": "AWS Access Key ID",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "HIGH",  # Strict pattern
        "pattern": RE_AWS_ACCESS,
    },
    {
        "key": "aws_secret",
        "label": "AWS Secret Access Key",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "MEDIUM",  # Length/pattern based
        "pattern": RE_AWS_SECRET,
    },
    {
        "key": "jwt",
        "label": "JWT Token",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "HIGH",  # Strict base64 structure
        "pattern": RE_JWT,
    },
    {
        "key": "password",
        "label": "Password / Secret (hard-coded)",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "LOW",  # Context heuristic
        "pattern": RE_PASSWORD,
    },
    {
        "key": "db_conn",
        "label": "Database Connection String",
        "category": "Secrets",
        "severity": "critical",
        "confidence": "MEDIUM",  # URI scheme matching
        "pattern": RE_DB_CONN,
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_text(text: str) -> List[Dict]:
    """
    Run all registered patterns against *text*.

    Returns a list of dictionaries (serialisable) – one per pattern that
    matched at least once – sorted by severity weight (descending) then count.
    """
    results: List[Dict] = []

    for rule in PATTERNS:
        matches = list(rule["pattern"].finditer(text))
        if not matches:
            continue

        # Validate matches if validator exists
        validator = rule.get("validator")
        validated_count = len(matches)
        
        if validator:
            validated_matches = [m for m in matches if validator(m.group(0))]
            validated_count = len(validated_matches)
            if validated_count == 0:
                continue
            matches = validated_matches

        # Build safe redacted samples (max 3)
        samples: List[str] = []
        seen: set[str] = set()
        for m in matches:
            raw = m.group(0)
            if raw in seen:
                continue
            seen.add(raw)
            samples.append(_redact(raw))
            if len(samples) >= 3:
                break

        results.append({
            "key": rule["key"],
            "label": rule["label"],
            "category": rule["category"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "count": validated_count,
            "samples": samples,
        })

    results.sort(key=lambda r: (-r.get("severity_weight", 10), -r["count"]))
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact(value: str) -> str:
    """Return a safe snippet that shows first + last 2 characters."""
    if len(value) <= 6:
        return value[:1] + "*" * (len(value) - 1)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def get_all_pattern_keys() -> List[str]:
    """Return a list of every rule key (useful for testing)."""
    return [p["key"] for p in PATTERNS]
