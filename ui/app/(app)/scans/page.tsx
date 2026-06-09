"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import * as api from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import NewScan from "@/components/NewScan";
import { SEV_ORDER, SEV_STYLE, StatusBadge, riskBand, timeAgo } from "@/lib/ui";

export default function ScansPage() {
  const [scans, setScans] = useState<api.ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .listScans(200)
        .then((r) => alive && setScans(r.scans))
        .catch(() => {})
        .finally(() => alive && setLoading(false));
    load();
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  return (
    <div>
      <PageHeader title="Scans" subtitle="Every engagement, newest first." />
      <div className="px-8 py-6">
        <NewScan />

        <div className="mt-6 overflow-hidden rounded-xl border border-[#1b2330]">
          <div className="grid grid-cols-[auto_1fr_auto_auto_auto] gap-4 border-b border-[#161d28] bg-[#0c1018] px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
            <span>Status</span>
            <span>Target</span>
            <span className="hidden sm:block">Findings</span>
            <span>Risk</span>
            <span className="text-right">When</span>
          </div>
          {loading ? (
            <Empty>Loading…</Empty>
          ) : scans.length === 0 ? (
            <Empty>No scans yet.</Empty>
          ) : (
            scans.map((s) => (
              <Link
                key={s.scan_id}
                href={`/scans/${s.scan_id}`}
                className="grid grid-cols-[auto_1fr_auto_auto_auto] items-center gap-4 border-b border-[#11161f] px-4 py-3 text-sm transition last:border-0 hover:bg-white/[0.03]"
              >
                <StatusBadge status={s.status} />
                <span className="truncate font-mono text-xs text-gray-300">{s.target}</span>
                <span className="hidden gap-1.5 sm:flex">
                  {SEV_ORDER.map((sev) =>
                    s.severity_counts[sev] ? (
                      <span
                        key={sev}
                        className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${SEV_STYLE[sev].bg} ${SEV_STYLE[sev].text}`}
                      >
                        {s.severity_counts[sev]} {sev[0].toUpperCase()}
                      </span>
                    ) : null
                  )}
                  {s.findings_count === 0 && <span className="text-xs text-gray-600">—</span>}
                </span>
                <span className={`text-xs font-bold ${s.risk_score != null ? riskBand(s.risk_score).color : "text-gray-600"}`}>
                  {s.risk_score ?? "—"}
                </span>
                <span className="text-right text-xs text-gray-600">{timeAgo(s.created_at)}</span>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="px-4 py-10 text-center text-sm text-gray-600">{children}</div>;
}
