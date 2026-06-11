import { useCallback, useState } from "react";
import type { ScanResult } from "./lib/types";
import { extractText, formatBytes } from "./lib/extractor";
import { scanText } from "./lib/detector";
import { computeRisk, buildRecommendations, RISK_COLORS } from "./lib/riskEngine";
import { FileDropzone } from "./components/FileDropzone";
import { RiskScoreBadge } from "./components/RiskScoreBadge";
import { FindingsTable } from "./components/FindingsTable";
import { RecommendationsList } from "./components/RecommendationsList";
import { ScoreBreakdown } from "./components/ScoreBreakdown";

export default function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFile = useCallback(async (file: File) => {
    setLoading(true);
    setError(null);
    setResult(null);

    const t0 = performance.now();

    try {
      // 1. Extract text
      const { text, sizeBytes } = await extractText(file);

      // 2. Scan
      const findings = scanText(text);

      // 3. Score
      const riskResult = computeRisk(findings);
      const recs = buildRecommendations(findings);
      const totalFindings = findings.reduce((sum, f) => sum + f.count, 0);
      const elapsed = Math.round((performance.now() - t0) * 100) / 100;

      setResult({
        status: "success",
        filename: file.name,
        size_bytes: sizeBytes,
        total_characters: text.length,
        score: riskResult.score,
        risk_level: riskResult.riskLevel,
        total_findings: totalFindings,
        findings,
        breakdown: riskResult.breakdown,
        cooccurrence_bonus: riskResult.cooccurrenceBonus,
        raw_score: riskResult.rawScore,
        recommendations: recs,
        elapsed_ms: elapsed,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error occurred";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  const hasFindings = result && result.findings.length > 0;
  const riskColors = result ? RISK_COLORS[result.risk_level] : RISK_COLORS.LOW;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-indigo-50/40">
      {/* Header */}
      <header className="border-b border-slate-200 bg-white/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-600 to-violet-700 shadow-lg shadow-indigo-200">
              <svg
                className="h-5 w-5 text-white"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M12 8v4" />
                <path d="M12 16h.01" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-slate-900">
                Compliance Risk Scanner
              </h1>
              <p className="text-xs text-slate-500">
                PII & Secrets Detection with Advanced Risk Scoring
              </p>
            </div>
          </div>
          
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-10">
        {/* Hero */}
        <div className="mb-10 text-center">
          <h2 className="text-3xl font-bold tracking-tight text-slate-900 sm:text-4xl">
            Document Compliance Report
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-base text-slate-600">
            Upload a document to detect PII, secrets, and credentials.
          </p>
        </div>

        {/* Drop zone */}
        <div className="mb-10">
          <FileDropzone onFile={handleFile} loading={loading} />
        </div>

        {/* Global error */}
        {error && (
          <div className="mb-8 rounded-xl border border-red-200 bg-red-50 p-5">
            <div className="flex gap-3">
              <svg className="mt-0.5 h-5 w-5 flex-shrink-0 text-red-500" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10A8 8 0 112 10a8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <div>
                <p className="text-sm font-semibold text-red-800">Scan failed</p>
                <p className="mt-0.5 text-sm text-red-600">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Loading state */}
        {loading && (
          <div className="flex justify-center py-16">
            <div className="flex flex-col items-center gap-4">
              <div className="relative h-16 w-16">
                <div className="absolute inset-0 animate-spin rounded-full border-4 border-slate-200" />
                <div className="absolute inset-0 animate-spin rounded-full border-4 border-indigo-600 border-t-transparent" />
              </div>
              <p className="text-sm font-medium text-slate-600">Analyzing document…</p>
              <p className="text-xs text-slate-400">Running detection patterns with validation</p>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="space-y-8">
            {/* Score Card */}
            <div className={`overflow-hidden rounded-2xl border ${riskColors.border} bg-white shadow-lg`}>
              <div className={`h-2 w-full bg-gradient-to-r ${riskColors.gradient}`} />
              <div className="grid gap-0 md:grid-cols-5">
                {/* Score Circle */}
                <div className="flex items-center justify-center p-8 md:col-span-2 md:border-r md:border-slate-100">
                  <RiskScoreBadge 
                    score={result.score} 
                    level={result.risk_level} 
                    colors={riskColors}
                  />
                </div>

                {/* Stats */}
                <div className="p-8 md:col-span-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900">
                        Risk Assessment Summary
                      </h3>
                      <p className="mt-1 text-sm text-slate-500">
                        Completed in {result.elapsed_ms.toFixed(0)} ms · {Object.keys(result.breakdown).length} categories detected
                      </p>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${riskColors.chip}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${riskColors.ring.replace("stroke-", "bg-")}`} />
                      {result.risk_level} RISK
                    </span>
                  </div>

                  <dl className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <StatCard
                      label="File"
                      value={result.filename.length > 18 ? result.filename.slice(0, 16) + "…" : result.filename}
                      sub={formatBytes(result.size_bytes)}
                    />
                    <StatCard
                      label="Characters"
                      value={result.total_characters.toLocaleString()}
                    />
                    <StatCard
                      label="Total Findings"
                      value={result.total_findings.toLocaleString()}
                      highlight={result.total_findings > 0}
                      highlightColor={result.risk_level === "CRITICAL" ? "red" : result.risk_level === "HIGH" ? "orange" : "amber"}
                    />
                    <StatCard
                      label="Co-occur. Bonus"
                      value={`+${result.cooccurrence_bonus}`}
                      sub={`Raw: ${result.raw_score.toFixed(1)}`}
                      highlight={result.cooccurrence_bonus > 0}
                      highlightColor="indigo"
                    />
                  </dl>
                </div>
              </div>
            </div>

            {/* Score Breakdown */}
            {Object.keys(result.breakdown).length > 0 && (
              <ScoreBreakdown breakdown={result.breakdown} />
            )}

            {/* Findings Table */}
            <section>
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-semibold text-slate-900">
                    Detected Findings
                  </h3>
                  <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
                    {result.findings.length}
                  </span>
                </div>
                <span className="text-sm text-slate-500">
                  {hasFindings ? "Sorted by confidence" : "Clean report"}
                </span>
              </div>
              <FindingsTable findings={result.findings} />
            </section>

            {/* Recommendations */}
            {result.recommendations.length > 0 && (
              <section>
                <RecommendationsList recommendations={result.recommendations} />
              </section>
            )}
          </div>
        )}

        {/* Empty state - Detection Coverage */}
        {!result && !loading && !error && (
          <div className="mt-8 rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
            <h3 className="text-center text-sm font-semibold text-slate-700 mb-6">
              Detection Coverage (12 patterns with checksum validation)
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
              {[
                { label: "Email", cat: "PII", conf: "MED" },
                { label: "Phone (India)", cat: "PII", conf: "MED" },
                { label: "PAN Card", cat: "PII", conf: "HIGH" },
                { label: "Aadhaar", cat: "PII", conf: "HIGH" },
                { label: "Passport", cat: "PII", conf: "MED" },
                { label: "Credit Card", cat: "PII", conf: "HIGH" },
                { label: "API Keys", cat: "Secret", conf: "LOW" },
                { label: "AWS Keys", cat: "Secret", conf: "HIGH" },
                { label: "JWT Tokens", cat: "Secret", conf: "HIGH" },
                { label: "Passwords", cat: "Secret", conf: "LOW" },
                { label: "DB Strings", cat: "Secret", conf: "MED" },
                { label: "AWS Secrets", cat: "Secret", conf: "MED" },
              ].map((p) => (
                <div
                  key={p.label}
                  className="flex items-center gap-2 rounded-lg bg-slate-50 px-3 py-2.5 text-xs transition-colors hover:bg-slate-100"
                >
                  <span
                    className={`h-2 w-2 rounded-full ${
                      p.cat === "Secret" ? "bg-rose-500" : "bg-blue-500"
                    }`}
                  />
                  <span className="font-medium text-slate-700">{p.label}</span>
                  <span
                    className={`ml-auto rounded px-1.5 py-0.5 text-[10px] font-semibold ${
                      p.conf === "HIGH"
                        ? "bg-emerald-100 text-emerald-700"
                        : p.conf === "MED"
                        ? "bg-amber-100 text-amber-700"
                        : "bg-slate-200 text-slate-600"
                    }`}
                  >
                    {p.conf}
                  </span>
                </div>
              ))}
            </div>
            
            <div className="mt-8 rounded-xl bg-slate-50 p-5">
              <h4 className="text-sm font-semibold text-slate-800 mb-3">
                Scoring Formula
              </h4>
              <div className="grid gap-4 text-xs text-slate-600 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg bg-white p-3 ring-1 ring-slate-200">
                  <p className="font-semibold text-indigo-600 mb-1">Step 1: Base Weight</p>
                  <p>Aadhaar: 35, PAN/Passport/Card/AWS: 30, API/JWT/DB: 25, Phone: 15, Email: 10</p>
                </div>
                <div className="rounded-lg bg-white p-3 ring-1 ring-slate-200">
                  <p className="font-semibold text-indigo-600 mb-1">Step 2: Confidence</p>
                  <p>HIGH checksum validation: ×1.0, MEDIUM regex: ×0.7, LOW heuristic: ×0.4</p>
                </div>
                <div className="rounded-lg bg-white p-3 ring-1 ring-slate-200">
                  <p className="font-semibold text-indigo-600 mb-1">Step 3: Volume</p>
                  <p>1× for single, 1.3× (2-5), 1.6× (6-20), 2× (21-100), 2.5× (100+)</p>
                </div>
                <div className="rounded-lg bg-white p-3 ring-1 ring-slate-200">
                  <p className="font-semibold text-indigo-600 mb-1">Step 4: Bonus</p>
                  <p>+5 for 2 categories, +12 for 3+. Final = MIN(100, Raw + Bonus)</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="border-t border-slate-200 bg-white/50">
        <div className="mx-auto max-w-6xl px-6 py-6 text-center text-xs text-slate-500">
          <p>
            Final Score = MIN(100, Σ(Weight × Confidence × Volume) + Co-occurrence Bonus)
          </p>
          <p className="mt-1">
            Risk Levels: 0-29 LOW · 30-59 MEDIUM · 60-84 HIGH · 85-100 CRITICAL
          </p>
        </div>
      </footer>
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
  highlight,
  highlightColor = "amber",
}: {
  label: string;
  value: string;
  sub?: string;
  highlight?: boolean;
  highlightColor?: "amber" | "orange" | "red" | "indigo";
}) {
  const colorClasses = {
    amber: "bg-amber-50 ring-amber-200 text-amber-700",
    orange: "bg-orange-50 ring-orange-200 text-orange-700",
    red: "bg-red-50 ring-red-200 text-red-700",
    indigo: "bg-indigo-50 ring-indigo-200 text-indigo-700",
  };

  return (
    <div
      className={`rounded-lg p-3 ring-1 ${
        highlight ? colorClasses[highlightColor] : "bg-slate-50 ring-slate-100"
      }`}
    >
      <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </dt>
      <dd
        className={`mt-1 text-lg font-semibold tabular-nums ${
          highlight ? "" : "text-slate-900"
        }`}
      >
        {value}
      </dd>
      {sub && <dd className="text-xs text-slate-400">{sub}</dd>}
    </div>
  );
}
