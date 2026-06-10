/**
 * riskEngine.ts
 * Compliance Risk Scoring engine.
 *
 * SCORING ALGORITHM:
 * Final Score = min(100, RawScore + CoOccurrenceBonus)
 * RawScore    = sum of contributions from each detected data type
 *
 * STEP 1 — SEVERITY WEIGHTS:
 *   aadhaar: 35, pan: 30, passport: 30, credit_card: 30, aws_access: 30, aws_secret: 30
 *   api_key: 25, jwt: 25, db_conn: 25
 *   password: 20, phone_in: 15, email: 10
 *
 * STEP 2 — CONFIDENCE FACTOR:
 *   HIGH: 1.0, MEDIUM: 0.7, LOW: 0.4
 *
 * STEP 3 — VOLUME MULTIPLIER:
 *   0: 0, 1: 1.0, 2-5: 1.3, 6-20: 1.6, 21-100: 2.0, >100: 2.5
 *
 * STEP 4 — PER-TYPE CONTRIBUTION:
 *   contribution = severity_weight × confidence_factor × volume_multiplier
 *
 * STEP 5 — CO-OCCURRENCE BONUS:
 *   1 category: 0, 2 categories: 5, 3+: 12
 *
 * STEP 6 — RISK LEVEL:
 *   0-29: LOW, 30-59: MEDIUM, 60-84: HIGH, 85-100: CRITICAL
 */
import type { Finding, BreakdownEntry } from "./types";

// Severity weights for each data type
const SEVERITY_WEIGHTS: Record<string, number> = {
  aadhaar: 35,
  pan: 30,
  passport: 30,
  credit_card: 30,
  aws_access: 30,
  aws_secret: 30,
  api_key: 25,
  jwt: 25,
  db_conn: 25,
  password: 20,
  phone_in: 15,
  email: 10,
};

// Confidence factors
const CONFIDENCE_FACTORS: Record<string, number> = {
  HIGH: 1.0,
  MEDIUM: 0.7,
  LOW: 0.4,
};

// Volume multiplier based on count
function getVolumeMultiplier(count: number): number {
  if (count === 0) return 0;
  if (count === 1) return 1.0;
  if (count <= 5) return 1.3;
  if (count <= 20) return 1.6;
  if (count <= 100) return 2.0;
  return 2.5;
}

// Classify risk level from score
export function classifyRiskLevel(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score <= 29) return "LOW";
  if (score <= 59) return "MEDIUM";
  if (score <= 84) return "HIGH";
  return "CRITICAL";
}

// Color schemes for risk levels
export const RISK_COLORS = {
  LOW: {
    ring: "stroke-emerald-500",
    bg: "bg-emerald-50",
    border: "border-emerald-200",
    text: "text-emerald-700",
    label: "text-emerald-900",
    sublabel: "text-emerald-600",
    chip: "bg-emerald-100 text-emerald-800",
    gradient: "from-emerald-500 to-teal-600",
    icon: "text-emerald-500",
  },
  MEDIUM: {
    ring: "stroke-amber-500",
    bg: "bg-amber-50",
    border: "border-amber-200",
    text: "text-amber-700",
    label: "text-amber-900",
    sublabel: "text-amber-600",
    chip: "bg-amber-100 text-amber-800",
    gradient: "from-amber-500 to-orange-500",
    icon: "text-amber-500",
  },
  HIGH: {
    ring: "stroke-orange-500",
    bg: "bg-orange-50",
    border: "border-orange-200",
    text: "text-orange-700",
    label: "text-orange-900",
    sublabel: "text-orange-600",
    chip: "bg-orange-100 text-orange-800",
    gradient: "from-orange-500 to-red-500",
    icon: "text-orange-500",
  },
  CRITICAL: {
    ring: "stroke-red-600",
    bg: "bg-red-50",
    border: "border-red-200",
    text: "text-red-700",
    label: "text-red-900",
    sublabel: "text-red-600",
    chip: "bg-red-100 text-red-800",
    gradient: "from-red-500 to-rose-600",
    icon: "text-red-500",
  },
} as const;

// Recommendation mapping
const RECOMMENDATION_MAP: Record<string, string> = {
  email:
    "Email addresses detected – classify dataset as PII under GDPR / DPDP Act and implement access controls.",
  phone_in:
    "Indian phone numbers detected – ensure consent records exist per DPDP Act 2023.",
  pan:
    "PAN card numbers found – sensitive financial PII. Encrypt at rest (AES-256) and enable audit logging.",
  aadhaar:
    "Aadhaar numbers discovered – UIDAI regulations restrict storage. Anonymize or tokenize immediately.",
  passport:
    "Passport numbers detected – treat as high-sensitivity identity data and notify your DPO.",
  credit_card:
    "Payment card data detected – verify PCI-DSS compliance, ensure PAN masking and tokenization.",
  api_key:
    "Hard-coded API keys found – rotate credentials immediately and move to secrets manager.",
  aws_access:
    "AWS Access Key IDs detected – CRITICAL. Rotate keys now, review CloudTrail, enforce least-privilege.",
  aws_secret:
    "AWS Secret Keys exposed – immediately rotate, invalidate sessions, audit AWS access for 90 days.",
  jwt:
    "JWT tokens discovered – revoke signing key, invalidate sessions, never log tokens in plaintext.",
  password:
    "Hard-coded passwords detected – migrate to secrets vault, force rotation, add pre-commit scanning.",
  db_conn:
    "Database connection strings with credentials found – move credentials to env vars, rotate passwords.",
};

// Main scoring function
export function computeRisk(findings: Finding[]): {
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  breakdown: Record<string, BreakdownEntry>;
  cooccurrenceBonus: number;
  rawScore: number;
} {
  const breakdown: Record<string, BreakdownEntry> = {};
  let rawScore = 0;
  let activeCategories = 0;

  for (const finding of findings) {
    const { key, count, confidence } = finding;
    if (count === 0) continue;

    const severityWeight = SEVERITY_WEIGHTS[key] ?? 10;
    const confidenceFactor = CONFIDENCE_FACTORS[confidence] ?? 0.7;
    const volumeMultiplier = getVolumeMultiplier(count);

    const contribution = Math.round(severityWeight * confidenceFactor * volumeMultiplier * 100) / 100;

    breakdown[key] = {
      count,
      confidence,
      severity_weight: severityWeight,
      confidence_factor: confidenceFactor,
      volume_multiplier: volumeMultiplier,
      contribution,
    };

    rawScore += contribution;
    activeCategories++;
  }

  // Co-occurrence bonus
  let cooccurrenceBonus = 0;
  if (activeCategories === 2) {
    cooccurrenceBonus = 5;
  } else if (activeCategories >= 3) {
    cooccurrenceBonus = 12;
  }

  const finalScore = Math.min(100, Math.round(rawScore + cooccurrenceBonus));
  const riskLevel = classifyRiskLevel(finalScore);

  return {
    score: finalScore,
    riskLevel,
    breakdown,
    cooccurrenceBonus,
    rawScore: Math.round(rawScore * 100) / 100,
  };
}

// Build recommendations
export function buildRecommendations(findings: Finding[]): string[] {
  // Sort by severity weight descending
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_WEIGHTS[b.key] ?? 0) - (SEVERITY_WEIGHTS[a.key] ?? 0)
  );

  const recs: string[] = [];
  const seen = new Set<string>();

  for (const finding of sorted) {
    const msg = RECOMMENDATION_MAP[finding.key];
    if (msg && !seen.has(finding.key)) {
      recs.push(msg);
      seen.add(finding.key);
    }
  }

  if (findings.length > 0) {
    recs.push(
      "Implement continuous automated secret scanning in CI/CD pipelines (GitLeaks, TruffleHog)."
    );
    recs.push(
      "Educate engineering teams on secure handling of PII and secrets via mandatory security training."
    );
  }

  return recs;
}

// Legacy wrapper for backward compatibility
export function computeRiskLegacy(findings: Finding[]): number {
  return computeRisk(findings).score;
}

export function classifyTier(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  return classifyRiskLevel(score);
}
