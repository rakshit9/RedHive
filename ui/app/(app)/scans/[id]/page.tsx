"use client";

import { useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import * as api from "@/lib/api";
import LogTerminal from "@/components/LogTerminal";
import SwarmView from "@/components/SwarmView";
import RiskGauge from "@/components/RiskGauge";
import FindingCard from "@/components/FindingCard";
import { AttackChainCard, PatchCard } from "@/components/ResultExtras";
import { SEV_ORDER, SEV_STYLE, StatusBadge } from "@/lib/ui";

const ACTIVE = (s?: string) => s === "queued" || s === "running";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<api.ScanDetail | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [tab, setTab] = useState<"findings" | "chains" | "patches">("findings");
  const [notFound, setNotFound] = useState(false);
  const [prBusy, setPrBusy] = useState(false);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [prErr, setPrErr] = useState<string | null>(null);
  const stopRef = useRef<(() => void) | null>(null);

  async function openPr() {
    setPrBusy(true);
    setPrErr(null);
    try {
      const res = await api.openPullRequest(id);
      setPrUrl(res.pr_url);
    } catch (e) {
      setPrErr(e instanceof api.ApiError ? e.message : "Could not open PR.");
    } finally {
      setPrBusy(false);
    }
  }

  // Initial load + live streaming for active scans.
  useEffect(() => {
    let alive = true;
    let poll: ReturnType<typeof setInterval> | null = null;

    api
      .getScan(id)
      .then((s) => {
        if (!alive) return;
        setScan(s);
        setLog(s.log || []);
        if (ACTIVE(s.status)) {
          // Stream new log lines; the initial log array is replaced live.
          setLog([]);
          stopRef.current = api.streamLog(
            id,
            (line) => setLog((p) => [...p, line]),
            () => api.getScan(id).then((fin) => alive && setScan(fin)).catch(() => {})
          );
          // Poll the structured results while running.
          poll = setInterval(() => {
            api.getScan(id).then((fin) => {
              if (!alive) return;
              setScan(fin);
              if (!ACTIVE(fin.status) && poll) {
                clearInterval(poll);
                poll = null;
              }
            }).catch(() => {});
          }, 4000);
        }
      })
      .catch(() => alive && setNotFound(true));

    return () => {
      alive = false;
      stopRef.current?.();
      if (poll) clearInterval(poll);
    };
  }, [id]);

  if (notFound) {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-gray-500">
        Scan not found.{" "}
        <Link href="/scans" className="ml-1 text-hive-accent hover:underline">
          Back to scans
        </Link>
      </div>
    );
  }

  const live = ACTIVE(scan?.status);
  const findings = [...(scan?.findings || [])].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );
  const chains = scan?.attack_chains || [];
  const patches = scan?.patches || [];

  return (
    <div>
      {/* Header */}
      <div className="border-b border-[#161d28] px-8 py-5">
        <Link href="/scans" className="text-xs text-gray-500 hover:text-gray-300">
          ← Scans
        </Link>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <h1 className="truncate font-mono text-lg text-gray-100">
              {scan?.target}
            </h1>
            <div className="mt-1 flex items-center gap-3">
              <StatusBadge status={scan?.status || "queued"} />
              {scan?.regression_summary && (
                <span className="text-xs text-gray-500">
                  🆕 {scan.regression_summary.new} · ♻️ {scan.regression_summary.recurring} · ✅{" "}
                  {scan.regression_summary.fixed}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-5">
            {!live && scan?.usage?.tokens != null && (
              <div className="rounded-lg border border-[#1b2330] bg-[#0c1018]/70 px-3 py-2 text-right">
                <div className="text-sm font-semibold text-gray-200">
                  {scan.usage.tokens.toLocaleString()} tokens
                </div>
                <div className="text-[10px] text-gray-500">
                  {scan.usage.llm_calls} LLM calls · ~${scan.usage.cost_usd?.toFixed(4)}
                </div>
              </div>
            )}
            {!live && <RiskGauge score={scan?.risk_score ?? null} />}
            {scan?.status === "done" && (
              <div className="flex flex-col gap-1.5">
                <a
                  href={api.reportUrl(id, "markdown")}
                  className="rounded-lg border border-[#1b2330] px-3 py-1.5 text-xs text-gray-300 hover:bg-white/5"
                >
                  ↓ Markdown report
                </a>
                <a
                  href={api.reportUrl(id, "json")}
                  className="rounded-lg border border-[#1b2330] px-3 py-1.5 text-xs text-gray-300 hover:bg-white/5"
                >
                  ↓ JSON report
                </a>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Live parallel agent-swarm visualizer */}
      <div className="px-8 pt-6">
        <SwarmView log={log} />
      </div>

      <div className="grid grid-cols-1 gap-6 px-8 pb-6 lg:grid-cols-2">
        {/* Live log */}
        <div className="lg:sticky lg:top-6 lg:self-start">
          <LogTerminal log={log} live={live} />
        </div>

        {/* Results */}
        <div>
          {/* Severity tiles */}
          <div className="mb-4 grid grid-cols-5 gap-2">
            {SEV_ORDER.map((sev) => {
              const n = scan?.severity_counts?.[sev] || 0;
              return (
                <div
                  key={sev}
                  className={`rounded-lg border px-2 py-2 text-center ${n ? SEV_STYLE[sev].bg : "border-[#1b2330]"}`}
                >
                  <div className={`text-lg font-bold ${n ? SEV_STYLE[sev].text : "text-gray-700"}`}>
                    {n}
                  </div>
                  <div className="text-[9px] uppercase text-gray-500">{sev}</div>
                </div>
              );
            })}
          </div>

          {/* Tabs */}
          <div className="mb-3 flex gap-1 border-b border-[#161d28]">
            <Tab id="findings" tab={tab} setTab={setTab} count={findings.length}>
              Findings
            </Tab>
            <Tab id="chains" tab={tab} setTab={setTab} count={chains.length}>
              Attack chains
            </Tab>
            <Tab id="patches" tab={tab} setTab={setTab} count={patches.length}>
              Fixes
            </Tab>
          </div>

          {tab === "findings" && (
            <div className="space-y-2.5">
              {findings.length === 0 ? (
                <Empty>{live ? "Agents are testing…" : "No findings."}</Empty>
              ) : (
                findings.map((f, i) => (
                  <div key={f.id || i} className="fade-in">
                    <FindingCard finding={f} />
                  </div>
                ))
              )}
            </div>
          )}

          {tab === "chains" && (
            <div className="space-y-3">
              {chains.length === 0 ? (
                <Empty>No attack chains identified.</Empty>
              ) : (
                chains.map((c, i) => <AttackChainCard key={i} chain={c} />)
              )}
            </div>
          )}

          {tab === "patches" && (
            <div className="space-y-3">
              {patches.length === 0 ? (
                <Empty>No suggested fixes.</Empty>
              ) : (
                <>
                  <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[#1b2330] bg-[#0c1018]/70 px-4 py-3">
                    <div className="flex-1 text-sm text-gray-300">
                      Open a pull request with these fixes on your connected repo.
                    </div>
                    {prUrl ? (
                      <a
                        href={prUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-500"
                      >
                        ✓ View pull request ↗
                      </a>
                    ) : (
                      <button
                        onClick={openPr}
                        disabled={prBusy}
                        className="rounded-lg bg-hive-accent px-4 py-2 text-xs font-semibold text-black hover:bg-amber-400 disabled:opacity-50"
                      >
                        {prBusy ? "Opening PR…" : "🐙 Open Pull Request"}
                      </button>
                    )}
                  </div>
                  {prErr && (
                    <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2 text-xs text-red-300">
                      {prErr}
                    </div>
                  )}
                  {patches.map((p, i) => (
                    <PatchCard key={i} patch={p} />
                  ))}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Tab({
  id,
  tab,
  setTab,
  count,
  children,
}: {
  id: "findings" | "chains" | "patches";
  tab: string;
  setTab: (t: "findings" | "chains" | "patches") => void;
  count: number;
  children: React.ReactNode;
}) {
  const active = tab === id;
  return (
    <button
      onClick={() => setTab(id)}
      className={`-mb-px border-b-2 px-3 py-2 text-sm transition ${
        active
          ? "border-hive-accent text-hive-accent"
          : "border-transparent text-gray-500 hover:text-gray-300"
      }`}
    >
      {children}
      <span className="ml-1.5 text-xs text-gray-600">{count}</span>
    </button>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-40 items-center justify-center rounded-xl border border-dashed border-[#1b2330] text-sm text-gray-600">
      {children}
    </div>
  );
}
