export interface BreakdownEntry {
  count: number;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  severity_weight: number;
  confidence_factor: number;
  volume_multiplier: number;
  contribution: number;
}

export interface Finding {
  key: string;
  label: string;
  category: "PII" | "Secrets";
  severity: "low" | "medium" | "high" | "critical";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  count: number;
  samples: string[];
}

export interface ScanResult {
  status: "success" | "error";
  filename: string;
  size_bytes: number;
  total_characters: number;
  score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  total_findings: number;
  findings: Finding[];
  breakdown: Record<string, BreakdownEntry>;
  cooccurrence_bonus: number;
  raw_score: number;
  recommendations: string[];
  elapsed_ms: number;
}

export const SEVERITY_STYLES: Record<
  Finding["severity"],
  { badge: string; dot: string; text: string }
> = {
  low: {
    badge: "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200",
    dot: "bg-emerald-500",
    text: "text-emerald-700",
  },
  medium: {
    badge: "bg-amber-50 text-amber-800 ring-1 ring-amber-200",
    dot: "bg-amber-500",
    text: "text-amber-700",
  },
  high: {
    badge: "bg-orange-50 text-orange-800 ring-1 ring-orange-200",
    dot: "bg-orange-500",
    text: "text-orange-700",
  },
  critical: {
    badge: "bg-rose-50 text-rose-700 ring-1 ring-rose-200",
    dot: "bg-rose-500",
    text: "text-rose-700",
  },
};
