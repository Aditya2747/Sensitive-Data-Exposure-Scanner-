import type { Finding } from "../lib/types";
import { SEVERITY_STYLES } from "../lib/types";

interface FindingsTableProps {
  findings: Finding[];
}

export function FindingsTable({ findings }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-6 text-center">
        <svg
          className="mx-auto h-10 w-10 text-emerald-500"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <polyline points="9 12 11 14 15 10" />
        </svg>
        <p className="mt-3 text-sm font-semibold text-emerald-800">
          No sensitive data detected
        </p>
        <p className="mt-1 text-xs text-emerald-600">
          Your document passed all 12 detection patterns.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      <table className="w-full text-sm">
        <thead className="bg-slate-50">
          <tr>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Category</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Finding</th>
            <th className="px-4 py-3 text-center font-semibold text-slate-700">Count</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Severity</th>
            <th className="px-4 py-3 text-left font-semibold text-slate-700">Sample</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((f) => {
            const s = SEVERITY_STYLES[f.severity];
            return (
              <tr key={f.key} className="hover:bg-slate-50 transition-colors">
                <td className="px-4 py-3">
                  <span
                    className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${
                      f.category === "Secrets"
                        ? "bg-rose-50 text-rose-700 ring-1 ring-rose-200"
                        : "bg-blue-50 text-blue-700 ring-1 ring-blue-200"
                    }`}
                  >
                    {f.category}
                  </span>
                </td>
                <td className="px-4 py-3 font-medium text-slate-900">{f.label}</td>
                <td className="px-4 py-3 text-center">
                  <span className="inline-flex h-7 min-w-[2rem] items-center justify-center rounded-full bg-slate-100 px-2 font-semibold tabular-nums text-slate-800">
                    {f.count}
                  </span>
                </td>
                 <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium capitalize ${s.badge}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                      {f.severity}
                    </span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                        f.confidence === "HIGH"
                          ? "bg-emerald-100 text-emerald-700"
                          : f.confidence === "MEDIUM"
                          ? "bg-amber-100 text-amber-700"
                          : "bg-slate-100 text-slate-600"
                      }`}
                    >
                      {f.confidence}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-500 max-w-xs truncate">
                  {f.samples.length > 0 ? (
                    <div className="space-y-0.5">
                      {f.samples.map((sample, i) => (
                        <div key={i} className="truncate">{sample}</div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-400 italic">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
