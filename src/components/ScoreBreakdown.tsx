import type { BreakdownEntry } from "../lib/types";

interface ScoreBreakdownProps {
  breakdown: Record<string, BreakdownEntry>;
}

export function ScoreBreakdown({ breakdown }: ScoreBreakdownProps) {
  const entries = Object.entries(breakdown).sort(
    (a, b) => b[1].contribution - a[1].contribution
  );

  const getConfidenceColor = (conf: string) => {
    switch (conf) {
      case "HIGH":
        return "bg-emerald-100 text-emerald-700";
      case "MEDIUM":
        return "bg-amber-100 text-amber-700";
      case "LOW":
        return "bg-slate-100 text-slate-600";
      default:
        return "bg-slate-100 text-slate-600";
    }
  };

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-100">
            <svg
              className="h-4 w-4 text-indigo-600"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 20h9" />
              <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
            </svg>
          </div>
          <h3 className="text-base font-semibold text-slate-900">
            Score Breakdown
          </h3>
        </div>
        <span className="text-xs text-slate-500">
          Contribution = Weight × Confidence × Volume
        </span>
      </div>

      <div className="space-y-3">
        {entries.map(([key, entry]) => (
          <div
            key={key}
            className="flex items-center gap-4 rounded-xl bg-slate-50 p-4"
          >
            {/* Contribution bar */}
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-slate-800">
                    {key.replace(/_/g, " ").toUpperCase()}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${getConfidenceColor(
                      entry.confidence
                    )}`}
                  >
                    {entry.confidence}
                  </span>
                  <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">
                    ×{entry.count}
                  </span>
                </div>
                <span className="text-sm font-bold text-indigo-600">
                  +{entry.contribution.toFixed(1)}
                </span>
              </div>
              
              {/* Progress bar */}
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-violet-500"
                  style={{ width: `${Math.min(100, (entry.contribution / 50) * 100)}%` }}
                />
              </div>
              
              {/* Formula breakdown */}
              <div className="mt-1.5 flex items-center gap-1 text-xs text-slate-500">
                <span>{entry.severity_weight}</span>
                <span>×</span>
                <span>{entry.confidence_factor}</span>
                <span>×</span>
                <span>{entry.volume_multiplier}</span>
                <span>=</span>
                <span className="font-medium text-slate-700">{entry.contribution}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
