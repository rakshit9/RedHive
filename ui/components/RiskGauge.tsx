import { riskBand } from "@/lib/ui";

// A compact circular risk gauge (0-100).
export default function RiskGauge({ score }: { score: number | null }) {
  const v = score ?? 0;
  const band = riskBand(v);
  const r = 34;
  const c = 2 * Math.PI * r;
  const dash = (v / 100) * c;
  const stroke =
    v >= 80 ? "#ef4444" : v >= 50 ? "#f87171" : v >= 20 ? "#f59e0b" : "#34d399";

  return (
    <div className="flex items-center gap-3">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 80 80" className="h-20 w-20 -rotate-90">
          <circle cx="40" cy="40" r={r} fill="none" stroke="#1b2330" strokeWidth="7" />
          <circle
            cx="40"
            cy="40"
            r={r}
            fill="none"
            stroke={stroke}
            strokeWidth="7"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${c}`}
            style={{ transition: "stroke-dasharray 0.6s ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold text-gray-100">{score ?? "—"}</span>
          <span className="text-[9px] text-gray-500">/ 100</span>
        </div>
      </div>
      <div>
        <div className={`text-sm font-bold ${band.color}`}>{band.label}</div>
        <div className="text-xs text-gray-500">risk score</div>
      </div>
    </div>
  );
}
