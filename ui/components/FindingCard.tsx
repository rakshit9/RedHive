"use client";

import { useState } from "react";
import type { Finding } from "@/lib/api";
import { SeverityBadge, RegressionTag } from "@/lib/ui";

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const hasDetail =
    finding.description ||
    finding.evidence ||
    (finding.reproduction && finding.reproduction.length) ||
    finding.remediation;

  return (
    <div className="overflow-hidden rounded-xl border border-[#1b2330] bg-[#0c1018]/70">
      <button
        onClick={() => hasDetail && setOpen(!open)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left"
      >
        <div className="mt-0.5">
          <SeverityBadge severity={finding.severity} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium text-gray-100">
              {finding.title}
            </span>
            <RegressionTag regression={finding.regression} />
          </div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-gray-500">
            {finding.category} · {finding.target}
          </div>
        </div>
        {hasDetail && (
          <span className="mt-1 text-gray-600">{open ? "▾" : "▸"}</span>
        )}
      </button>

      {open && hasDetail && (
        <div className="space-y-3 border-t border-[#161d28] px-4 py-3 text-sm">
          {finding.description && (
            <p className="text-gray-300">{finding.description}</p>
          )}
          {finding.evidence && (
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-500">
                Evidence
              </div>
              <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 font-mono text-[11px] text-gray-300">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.reproduction && finding.reproduction.length > 0 && (
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-gray-500">
                Reproduction
              </div>
              <ol className="list-inside list-decimal space-y-0.5 text-gray-300">
                {finding.reproduction.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </div>
          )}
          {finding.remediation && (
            <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3">
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-emerald-400">
                Remediation
              </div>
              <p className="text-gray-300">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
