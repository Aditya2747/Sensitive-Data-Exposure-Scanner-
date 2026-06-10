interface RiskScoreBadgeProps {
  score: number;
  level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  colors: {
    ring: string;
    bg: string;
    border: string;
    text: string;
    label: string;
    sublabel: string;
    chip: string;
    gradient: string;
    icon: string;
  };
}

export function RiskScoreBadge({ score, level, colors }: RiskScoreBadgeProps) {
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const displayScore = Math.round(score);

  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        <svg width="200" height="200" className="-rotate-90">
          {/* Background ring */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="#e2e8f0"
            strokeWidth="14"
          />
          {/* Progress ring */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            className={colors.ring}
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - progress}
            style={{ transition: "stroke-dashoffset 1s ease-in-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-5xl font-bold tracking-tight text-slate-900 tabular-nums">
            {displayScore}
          </span>
          <span className="text-sm font-medium text-slate-500">/ 100</span>
        </div>
      </div>

      <div className={`mt-5 inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-semibold ${colors.chip}`}>
        <span className={`h-2 w-2 rounded-full ${colors.ring.replace("stroke-", "bg-")}`} />
        {level} RISK
      </div>
    </div>
  );
}
