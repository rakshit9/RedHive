"use client";

import { useState } from "react";
import type { Finding, Severity } from "@/lib/api";

const SEV_STYLE: Record<Severity, { dot: string; text: string; ring: string }> = {
  critical: { dot: "bg-red-600", text: "text-red-400", ring: "border-red-900/60" },
  high: { dot: "bg-red-500", text: "text-red-400", ring: "border-red-900/50" },
  medium: { dot: "bg-amber-500", text: "text-amber-400", ring: "border-amber-900/50" },
  low: { dot: "bg-yellow-400", text: "text-yellow-300", ring: "border-yellow-900/40" },
  info: { dot: "bg-slate-500", text: "text-slate-400", ring: "border-slate-700/50" },
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const sev = (finding.severity || "info") as Severity;
  const style = SEV_STYLE[sev] ?? SEV_STYLE.info;

  return (
    <div className={`rounded-lg border ${style.ring} bg-hive-panel p-4`}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start justify-between gap-3 text-left"
      >
        <div className="flex items-start gap-3">
          <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${style.dot}`} />
          <div>
            <div className="font-medium text-gray-100">{finding.title}</div>
            <div className="mt-0.5 text-xs text-gray-500">
              {finding.category} · {finding.target}
            </div>
          </div>
        </div>
        <span className={`shrink-0 text-xs font-semibold uppercase ${style.text}`}>
          {sev}
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3 border-t border-hive-border pt-3 text-sm">
          {finding.description && (
            <div>
              <div className="text-xs font-semibold text-gray-500">DESCRIPTION</div>
              <p className="text-gray-300">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <div className="text-xs font-semibold text-gray-500">EVIDENCE</div>
              <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-2 text-xs text-gray-400">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.reproduction && finding.reproduction.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-gray-500">REPRODUCTION</div>
              <ol className="mt-1 list-decimal space-y-0.5 pl-5 text-gray-300">
                {finding.reproduction.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ol>
            </div>
          )}
          {finding.remediation && (
            <div>
              <div className="text-xs font-semibold text-hive-accent">
                AI REMEDIATION
              </div>
              <p className="text-gray-300">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
