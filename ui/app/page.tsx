"use client";

import { useEffect, useRef, useState } from "react";
import { getScan, startScan, streamLog, type Finding } from "@/lib/api";
import FindingCard from "@/components/FindingCard";
import Pipeline from "@/components/Pipeline";

type Status = "idle" | "running" | "done" | "failed";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-900/50",
  high: "text-red-400 border-red-900/50",
  medium: "text-amber-400 border-amber-900/50",
  low: "text-yellow-300 border-yellow-900/40",
  info: "text-slate-400 border-slate-700/50",
};

export default function Home() {
  const [target, setTarget] = useState("http://127.0.0.1:8766");
  const [status, setStatus] = useState<Status>("idle");
  const [log, setLog] = useState<string[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

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
  const running = status === "running";
  const finished = status === "done" || status === "failed";

  return (
    <div className="min-h-screen">
      {/* Top nav */}
      <header className="sticky top-0 z-10 border-b border-[#161d28] bg-[#07090e]/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3.5">
          <div className="flex items-center gap-2.5">
            <span className="text-xl">🐝</span>
            <span className="text-lg font-bold tracking-tight text-gray-100">
              Red<span className="text-hive-accent">Hive</span>
            </span>
            <span className="ml-2 hidden rounded-full border border-[#1b2330] px-2 py-0.5 text-[10px] uppercase tracking-wide text-gray-500 sm:inline">
              Autonomous Pentest
            </span>
          </div>
          <StatusBadge status={status} />
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        {/* Hero / scan bar */}
        <div className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight text-gray-100">
            Point the swarm at a target.
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            A team of AI agents maps the attack surface, reasons about what to
            test, validates findings, and writes the fixes.
          </p>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <span className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-600">
              ⌖
            </span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="http://localhost:3000"
              disabled={running}
              className="w-full rounded-xl border border-[#1b2330] bg-[#0c1018] py-3 pl-9 pr-4 text-sm text-gray-100 outline-none transition focus:border-hive-accent disabled:opacity-60"
              onKeyDown={(e) => e.key === "Enter" && !running && handleScan()}
            />
          </div>
          <button
            onClick={handleScan}
            disabled={running || !target.trim()}
            className="rounded-xl bg-hive-accent px-7 py-3 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? "Scanning…" : "Run Scan"}
          </button>
        </div>
        <p className="mt-2 text-xs text-gray-600">
          ⚠️ Authorized practice targets only — the allowlist is enforced
          server-side.
        </p>

        {error && (
          <div className="mt-4 rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300 fade-in">
            {error}
          </div>
        )}

        {/* Pipeline */}
        <div className="mt-6">
          <Pipeline log={log} finished={finished} />
        </div>

        {/* Stat tiles */}
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-6">
          <StatTile label="Findings" value={findings.length} accent />
          {SEV_ORDER.map((s) => (
            <StatTile key={s} label={s} value={counts[s] || 0} sev={s} />
          ))}
        </div>

        {/* Log + findings */}
        <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
          {/* Terminal-style log */}
          <section>
            <div className="overflow-hidden rounded-xl border border-[#1b2330] bg-[#0a0d13]">
              <div className="flex items-center gap-2 border-b border-[#161d28] bg-[#0c1018] px-4 py-2.5">
                <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
                <span className="ml-2 text-xs text-gray-500">agent log</span>
                {running && (
                  <span className="ml-auto flex items-center gap-1.5 text-xs text-amber-400">
                    <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-amber-400" />
                    live
                  </span>
                )}
              </div>
              <div className="log-scroll h-[440px] overflow-y-auto p-4 font-mono text-xs leading-relaxed">
                {log.length === 0 ? (
                  <span className="text-gray-600">
                    $ awaiting target… run a scan to watch the agents work.
                  </span>
                ) : (
                  log.map((line, i) => (
                    <div key={i} className={`fade-in ${lineColor(line)}`}>
                      <span className="select-none text-gray-700">›</span> {line}
                    </div>
                  ))
                )}
                <div ref={logEndRef} />
              </div>
            </div>
          </section>

          {/* Findings */}
          <section>
            <div className="mb-2 flex items-center justify-between px-1">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                Findings {findings.length > 0 && `· ${findings.length}`}
              </h2>
            </div>
            <div className="cards-scroll h-[440px] space-y-3 overflow-y-auto pr-1">
              {findings.length === 0 ? (
                <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-[#1b2330] text-sm text-gray-600">
                  {running ? "Agents are testing…" : "No findings yet."}
                </div>
              ) : (
                findings.map((f, i) => (
                  <div key={i} className="fade-in">
                    <FindingCard finding={f} />
                  </div>
                ))
              )}
            </div>
          </section>
        </div>

        <footer className="mt-10 border-t border-[#161d28] pt-4 text-center text-xs text-gray-600">
          RedHive · autonomous multi-agent pentest · LangGraph · FastAPI
        </footer>
      </main>
    </div>
  );
}

function StatTile({
  label,
  value,
  sev,
  accent,
}: {
  label: string;
  value: number;
  sev?: string;
  accent?: boolean;
}) {
  const border = accent
    ? "border-hive-accent/40"
    : sev && value > 0
    ? SEV_COLOR[sev]
    : "border-[#1b2330] text-gray-600";
  return (
    <div className={`rounded-xl border bg-[#0c1018]/70 px-3 py-3 ${border}`}>
      <div
        className={`text-2xl font-bold ${
          accent ? "text-hive-accent" : value > 0 ? "" : "text-gray-700"
        }`}
      >
        {value}
      </div>
      <div className="mt-0.5 text-[10px] uppercase tracking-wide text-gray-500">
        {label}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: Status }) {
  const map: Record<Status, { label: string; cls: string }> = {
    idle: { label: "Idle", cls: "bg-slate-800/60 text-slate-400" },
    running: { label: "● Running", cls: "bg-amber-950/60 text-amber-400" },
    done: { label: "✓ Complete", cls: "bg-emerald-950/60 text-emerald-400" },
    failed: { label: "✕ Failed", cls: "bg-red-950/60 text-red-400" },
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
