// Shared presentational helpers used across pages.

import type { Severity, ScanStatus, Regression } from "@/lib/api";

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEV_STYLE: Record<Severity, { text: string; bg: string; dot: string; label: string }> = {
  critical: { text: "text-red-300", bg: "bg-red-950/50 border-red-900/60", dot: "bg-red-500", label: "Critical" },
  high: { text: "text-red-400", bg: "bg-red-950/40 border-red-900/50", dot: "bg-red-500", label: "High" },
  medium: { text: "text-amber-400", bg: "bg-amber-950/40 border-amber-900/50", dot: "bg-amber-500", label: "Medium" },
  low: { text: "text-yellow-300", bg: "bg-yellow-950/30 border-yellow-900/40", dot: "bg-yellow-400", label: "Low" },
  info: { text: "text-slate-400", bg: "bg-slate-900/40 border-slate-700/50", dot: "bg-slate-500", label: "Info" },
};

export function riskBand(score: number): { label: string; color: string } {
  if (score >= 80) return { label: "CRITICAL", color: "text-red-400" };
  if (score >= 50) return { label: "HIGH", color: "text-red-400" };
  if (score >= 20) return { label: "MEDIUM", color: "text-amber-400" };
  return { label: "LOW", color: "text-emerald-400" };
}

export const STATUS_STYLE: Record<string, string> = {
  queued: "bg-slate-800/70 text-slate-300",
  running: "bg-amber-950/60 text-amber-300",
  done: "bg-emerald-950/60 text-emerald-300",
  failed: "bg-red-950/60 text-red-300",
  canceled: "bg-slate-800/70 text-slate-400",
};

export function StatusBadge({ status }: { status: ScanStatus | string }) {
  const cls = STATUS_STYLE[status] || "bg-slate-800/70 text-slate-300";
  const icon =
    status === "running" ? "●" : status === "done" ? "✓" : status === "failed" ? "✕" : "○";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      <span className={status === "running" ? "pulse-dot" : ""}>{icon}</span>
      {status}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV_STYLE[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold ${s.bg} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

const REG_STYLE: Record<Regression, string> = {
  new: "bg-sky-950/50 text-sky-300 border-sky-900/50",
  recurring: "bg-violet-950/50 text-violet-300 border-violet-900/50",
  fixed: "bg-emerald-950/50 text-emerald-300 border-emerald-900/50",
};

export function RegressionTag({ regression }: { regression?: Regression }) {
  if (!regression) return null;
  const icon = regression === "new" ? "🆕" : regression === "recurring" ? "♻️" : "✅";
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${REG_STYLE[regression]}`}>
      {icon} {regression}
    </span>
  );
}

export function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function logLineColor(line: string): string {
  if (line.includes("[error]")) return "text-red-400";
  if (line.includes("[worker]")) return "text-slate-500";
  if (line.includes("[manager]")) return "text-sky-400";
  if (line.includes("[recon]")) return "text-cyan-400";
  if (line.includes("[lead]")) return "text-violet-400";
  if (line.includes("[tester]")) return "text-amber-400";
  if (line.includes("[validator]")) return "text-emerald-400";
  if (line.includes("[reporter]")) return "text-pink-400";
  if (line.includes("[patch]")) return "text-orange-300";
  if (line.includes("[strategist]")) return "text-fuchsia-400";
  if (line.includes("[memory]")) return "text-teal-300";
  return "text-gray-400";
}
