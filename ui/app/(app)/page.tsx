"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import * as api from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import NewScan from "@/components/NewScan";
import { SEV_ORDER, SEV_STYLE, StatusBadge, riskBand, timeAgo } from "@/lib/ui";

export default function Dashboard() {
  const [scans, setScans] = useState<api.ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .listScans(100)
        .then((r) => alive && setScans(r.scans))
        .catch(() => {})
        .finally(() => alive && setLoading(false));
    load();
    // Light polling so queued/running scans update on the dashboard.
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const totals: Record<string, number> = {};
  let lastRisk: number | null = null;
  for (const s of scans) {
    for (const sev of SEV_ORDER) totals[sev] = (totals[sev] || 0) + (s.severity_counts[sev] || 0);
  }
  const done = scans.filter((s) => s.status === "done");
  if (done.length && done[0].risk_score != null) lastRisk = done[0].risk_score;
  const totalFindings = Object.values(totals).reduce((a, b) => a + b, 0);
  const running = scans.filter((s) => s.status === "running" || s.status === "queued").length;

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle="Your continuous security posture at a glance."
      />

      <div className="px-8 py-6">
        <NewScan />

        {/* KPI tiles */}
        <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Kpi label="Total scans" value={scans.length} />
          <Kpi label="Active" value={running} accent={running > 0} />
          <Kpi
            label="Latest risk"
            value={lastRisk ?? "—"}
            sub={lastRisk != null ? riskBand(lastRisk).label : undefined}
            subColor={lastRisk != null ? riskBand(lastRisk).color : undefined}
          />
          <Kpi label="Open findings" value={totalFindings} />
        </div>

        {/* Severity breakdown */}
        <div className="mt-3 grid grid-cols-5 gap-3">
          {SEV_ORDER.map((sev) => (
            <div
              key={sev}
              className={`rounded-xl border bg-[#0c1018]/70 px-3 py-3 ${
                totals[sev] ? SEV_STYLE[sev].bg : "border-[#1b2330]"
              }`}
            >
              <div className={`text-2xl font-bold ${totals[sev] ? SEV_STYLE[sev].text : "text-gray-700"}`}>
                {totals[sev] || 0}
              </div>
              <div className="mt-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                {SEV_STYLE[sev].label}
              </div>
            </div>
          ))}
        </div>

        {/* Recent scans */}
        <div className="mt-8 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-400">
            Recent scans
          </h2>
          <Link href="/scans" className="text-xs text-hive-accent hover:underline">
            View all →
          </Link>
        </div>

        <div className="mt-3 overflow-hidden rounded-xl border border-[#1b2330]">
          {loading ? (
            <Empty>Loading…</Empty>
          ) : scans.length === 0 ? (
            <Empty>No scans yet — run your first scan above.</Empty>
          ) : (
            scans.slice(0, 8).map((s) => <ScanRow key={s.scan_id} scan={s} />)
          )}
        </div>
      </div>
    </div>
  );
}

function ScanRow({ scan }: { scan: api.ScanSummary }) {
  return (
    <Link
      href={`/scans/${scan.scan_id}`}
      className="flex items-center gap-4 border-b border-[#11161f] px-4 py-3 text-sm transition last:border-0 hover:bg-white/[0.03]"
    >
      <StatusBadge status={scan.status} />
      <span className="flex-1 truncate font-mono text-xs text-gray-300">
        {scan.target}
      </span>
      <span className="hidden gap-1.5 sm:flex">
        {SEV_ORDER.map((sev) =>
          scan.severity_counts[sev] ? (
            <span
              key={sev}
              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${SEV_STYLE[sev].bg} ${SEV_STYLE[sev].text}`}
            >
              {scan.severity_counts[sev]} {sev[0].toUpperCase()}
            </span>
          ) : null
        )}
      </span>
      {scan.risk_score != null && (
        <span className={`text-xs font-bold ${riskBand(scan.risk_score).color}`}>
          {scan.risk_score}
        </span>
      )}
      <span className="w-16 text-right text-xs text-gray-600">
        {timeAgo(scan.created_at)}
      </span>
    </Link>
  );
}

function Kpi({
  label,
  value,
  sub,
  subColor,
  accent,
}: {
  label: string;
  value: number | string;
  sub?: string;
  subColor?: string;
  accent?: boolean;
}) {
  return (
    <div className={`rounded-xl border bg-[#0c1018]/70 px-4 py-4 ${accent ? "border-hive-accent/40" : "border-[#1b2330]"}`}>
      <div className={`text-2xl font-bold ${accent ? "text-hive-accent" : "text-gray-100"}`}>
        {value}
      </div>
      <div className="mt-0.5 text-[11px] uppercase tracking-wide text-gray-500">
        {label}
      </div>
      {sub && <div className={`mt-0.5 text-[10px] font-semibold ${subColor}`}>{sub}</div>}
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="px-4 py-10 text-center text-sm text-gray-600">{children}</div>
  );
}
