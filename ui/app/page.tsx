"use client";

import { useEffect, useRef, useState } from "react";
import { getScan, startScan, streamLog, type Finding } from "@/lib/api";
import FindingCard from "@/components/FindingCard";

type Status = "idle" | "running" | "done" | "failed";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export default function Home() {
  const [target, setTarget] = useState("http://localhost:3000");
  const [status, setStatus] = useState<Status>("idle");
  const [log, setLog] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll the log to the latest line.
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [log]);

  async function handleScan() {
    setError(null);
    setLog([]);
    setFindings([]);
    setStatus("running");
    try {
      const { scan_id } = await startScan(target.trim());

      streamLog(
        scan_id,
        (line) => setLog((prev) => [...prev, line]),
        async () => {
          const scan = await getScan(scan_id);
          setFindings(sortFindings(scan.findings || []));
          setStatus(scan.status === "failed" ? "failed" : "done");
        }
      );
    } catch (e: any) {
      setError(e.message || "Scan failed to start");
      setStatus("idle");
    }
  }

  const counts = countBySeverity(findings);

  return (
    <main className="mx-auto max-w-6xl px-6 py-8">
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🐝</span>
          <div>
            <h1 className="text-xl font-bold text-gray-100">RedHive</h1>
            <p className="text-xs text-gray-500">
              Autonomous multi-agent pentest platform
            </p>
          </div>
        </div>
        <StatusBadge status={status} />
      </div>

      {/* Target input */}
      <div className="mb-3 flex gap-2">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="http://localhost:3000"
          className="flex-1 rounded-lg border border-hive-border bg-hive-panel px-4 py-2.5 text-sm text-gray-100 outline-none focus:border-hive-accent"
          onKeyDown={(e) => e.key === "Enter" && status !== "running" && handleScan()}
        />
        <button
          onClick={handleScan}
          disabled={status === "running" || !target.trim()}
          className="rounded-lg bg-hive-accent px-6 py-2.5 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {status === "running" ? "Scanning…" : "Scan"}
        </button>
      </div>
      <p className="mb-6 text-xs text-gray-600">
        ⚠️ Authorized practice targets only (allowlist enforced server-side).
      </p>

      {error && (
        <div className="mb-6 rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Two-column layout: live log + findings */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        {/* Live log */}
        <section>
          <h2 className="mb-2 text-xs font-semibold uppercase text-gray-500">
            Live agent log
          </h2>
          <div className="log-scroll h-[460px] overflow-y-auto rounded-lg border border-hive-border bg-black/40 p-4 font-mono text-xs leading-relaxed">
            {log.length === 0 ? (
              <span className="text-gray-600">
                Run a scan to watch the agents work…
              </span>
            ) : (
              log.map((line, i) => (
                <div key={i} className={lineColor(line)}>
                  {line}
                </div>
              ))
            )}
            <div ref={logEndRef} />
          </div>
        </section>

        {/* Findings */}
        <section>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-xs font-semibold uppercase text-gray-500">
              Findings {findings.length > 0 && `(${findings.length})`}
            </h2>
            {findings.length > 0 && (
              <div className="flex gap-2 text-xs">
                {SEV_ORDER.filter((s) => counts[s]).map((s) => (
                  <span key={s} className="text-gray-400">
                    {counts[s]} {s}
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="h-[460px] space-y-3 overflow-y-auto">
            {findings.length === 0 ? (
              <div className="flex h-full items-center justify-center rounded-lg border border-dashed border-hive-border text-sm text-gray-600">
                {status === "running"
                  ? "Agents are testing…"
                  : "No findings yet."}
              </div>
            ) : (
              findings.map((f, i) => <FindingCard key={i} finding={f} />)
            )}
          </div>
        </section>
      </div>
    </main>
  );
}

function StatusBadge({ status }: { status: Status }) {
  const map: Record<Status, { label: string; cls: string }> = {
    idle: { label: "Idle", cls: "bg-slate-800 text-slate-400" },
    running: { label: "● Running", cls: "bg-amber-950 text-amber-400" },
    done: { label: "✓ Done", cls: "bg-emerald-950 text-emerald-400" },
    failed: { label: "✕ Failed", cls: "bg-red-950 text-red-400" },
  };
  const { label, cls } = map[status];
  return (
    <span className={`rounded-full px-3 py-1 text-xs font-medium ${cls}`}>
      {label}
    </span>
  );
}

function lineColor(line: string): string {
  if (line.includes("[error]")) return "text-red-400";
  if (line.includes("[manager]")) return "text-sky-400";
  if (line.includes("[recon]")) return "text-cyan-400";
  if (line.includes("[lead]")) return "text-violet-400";
  if (line.includes("[tester]")) return "text-amber-400";
  if (line.includes("[validator]")) return "text-emerald-400";
  if (line.includes("[reporter]")) return "text-pink-400";
  return "text-gray-400";
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  return findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank = (s: string) => {
    const i = (SEV_ORDER as readonly string[]).indexOf(s);
    return i === -1 ? 99 : i;
  };
  return [...findings].sort((a, b) => rank(a.severity) - rank(b.severity));
}
