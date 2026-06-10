/**
 * detector.ts
 * Regex-based sensitive-data scanner with confidence levels.
 * Mirrors backend/services/detector.py.
 *
 * CONFIDENCE LEVELS:
 *   HIGH   - Checksum/structure validated
 *   MEDIUM - Regex pattern match only
 *   LOW    - Heuristic/context-based
 */
import type { Finding } from "./types";

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function luhnChecksum(cardNumber: string): boolean {
  const digits = cardNumber.replace(/\D/g, "");
  if (digits.length < 13) return false;

  let sum = 0;
  let isEven = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isEven = !isEven;
  }
  return sum % 10 === 0;
}

function verhoeffChecksum(aadhaar: string): boolean {
  const digits = aadhaar.replace(/\D/g, "").split("").map(Number);
  if (digits.length !== 12) return false;

  const d: number[][] = [
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
  ];

  const p: number[][] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
  ];

  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = d[c][p[i % 8][digits[digits.length - 1 - i]]];
  }
  return c === 0;
}

function validatePan(pan: string): boolean {
  if (pan.length !== 10) return false;
  const first5 = pan.slice(0, 5);
  const middle4 = pan.slice(5, 9);
  const last1 = pan.slice(9);

  return (
    /^[A-Z]{5}$/.test(first5) &&
    /^\d{4}$/.test(middle4) &&
    /^[A-Z]$/.test(last1)
  );
}

// ---------------------------------------------------------------------------
// Compiled patterns
// ---------------------------------------------------------------------------

const RE_EMAIL =
  /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

const RE_PHONE_IN =
  /(?<![0-9])(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}(?![0-9])/g;

const RE_PAN = /\b[A-Z]{5}\d{4}[A-Z]\b/g;

const RE_AADHAAR =
  /(?<![0-9])[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![0-9])/g;

const RE_PASSPORT = /\b[A-Z][1-9]\d{6}\b/g;

const RE_CREDIT_CARD =
  /(?<!\d)(?:4\d{3}|5[1-5]\d{2}|6\d{3}|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d|(?:50|5[6-9]|6\d)\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}(?!\d)/g;

const RE_API_KEY =
  /(?:api[_-]?key|apikey|api secret|access[_\-]?key)[\s:=]+["']?([A-Za-z0-9_\-]{16,})["']?/gi;

const RE_AWS_ACCESS =
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b/g;

const RE_AWS_SECRET =
  /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)[\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi;

const RE_JWT =
  /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g;

const RE_PASSWORD =
  /(?:password|passwd|pwd|secret|token|private[_\-]?key)[\s:=]+["']?([^\s"',;]{8,})["']?/gi;

const RE_DB_CONN =
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|oracle|sqlite|amqp|amqps):\/\/[^\s"'<>]{6,}\b/gi;

// ---------------------------------------------------------------------------
// Rule definitions with confidence levels
// ---------------------------------------------------------------------------

interface Rule {
  key: string;
  label: string;
  category: "PII" | "Secrets";
  severity: "low" | "medium" | "high" | "critical";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  pattern: RegExp;
  validator?: (s: string) => boolean;
}

const RULES: Rule[] = [
  {
    key: "email",
    label: "Email Address",
    category: "PII",
    severity: "medium",
    confidence: "MEDIUM",
    pattern: RE_EMAIL,
  },
  {
    key: "phone_in",
    label: "Indian Phone Number",
    category: "PII",
    severity: "medium",
    confidence: "MEDIUM",
    pattern: RE_PHONE_IN,
  },
  {
    key: "pan",
    label: "PAN Card (India)",
    category: "PII",
    severity: "high",
    confidence: "HIGH",
    pattern: RE_PAN,
    validator: validatePan,
  },
  {
    key: "aadhaar",
    label: "Aadhaar Card (India)",
    category: "PII",
    severity: "high",
    confidence: "HIGH",
    pattern: RE_AADHAAR,
    validator: verhoeffChecksum,
  },
  {
    key: "passport",
    label: "Passport Number",
    category: "PII",
    severity: "high",
    confidence: "MEDIUM",
    pattern: RE_PASSPORT,
  },
  {
    key: "credit_card",
    label: "Credit / Debit Card",
    category: "PII",
    severity: "high",
    confidence: "HIGH",
    pattern: RE_CREDIT_CARD,
    validator: luhnChecksum,
  },
  {
    key: "api_key",
    label: "API Key / Token",
    category: "Secrets",
    severity: "critical",
    confidence: "LOW",
    pattern: RE_API_KEY,
  },
  {
    key: "aws_access",
    label: "AWS Access Key ID",
    category: "Secrets",
    severity: "critical",
    confidence: "HIGH",
    pattern: RE_AWS_ACCESS,
  },
  {
    key: "aws_secret",
    label: "AWS Secret Access Key",
    category: "Secrets",
    severity: "critical",
    confidence: "MEDIUM",
    pattern: RE_AWS_SECRET,
  },
  {
    key: "jwt",
    label: "JWT Token",
    category: "Secrets",
    severity: "critical",
    confidence: "HIGH",
    pattern: RE_JWT,
  },
  {
    key: "password",
    label: "Password / Secret (hard-coded)",
    category: "Secrets",
    severity: "critical",
    confidence: "LOW",
    pattern: RE_PASSWORD,
  },
  {
    key: "db_conn",
    label: "Database Connection String",
    category: "Secrets",
    severity: "critical",
    confidence: "MEDIUM",
    pattern: RE_DB_CONN,
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function redact(value: string): string {
  if (value.length <= 6) return value.slice(0, 1) + "*".repeat(value.length - 1);
  return value.slice(0, 2) + "*".repeat(value.length - 4) + value.slice(-2);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function scanText(text: string): Finding[] {
  const results: Finding[] = [];

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    const matches = [...text.matchAll(rule.pattern)];
    if (matches.length === 0) continue;

    // Validate if validator exists
    let validatedMatches = matches;
    if (rule.validator) {
      validatedMatches = matches.filter((m) => rule.validator!(m[0]));
      if (validatedMatches.length === 0) continue;
    }

    const seen = new Set<string>();
    const samples: string[] = [];
    for (const m of validatedMatches) {
      const raw = m[0];
      if (seen.has(raw)) continue;
      seen.add(raw);
      samples.push(redact(raw));
      if (samples.length >= 3) break;
    }

    results.push({
      key: rule.key,
      label: rule.label,
      category: rule.category,
      severity: rule.severity,
      confidence: rule.confidence,
      count: validatedMatches.length,
      samples,
    });
  }

  // Sort by confidence first (HIGH > MEDIUM > LOW), then by count
  const confidenceOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  results.sort(
    (a, b) =>
      confidenceOrder[a.confidence] - confidenceOrder[b.confidence] ||
      b.count - a.count
  );

  return results;
}
