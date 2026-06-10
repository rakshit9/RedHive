"use client";

// Live visualization of the parallel probe-agent swarm.
//
// It parses the streaming scan log (no extra API needed): the dispatch line
// tells us how many agents launched, and each "[XxxAgent] <url> → <result>"
// line marks one agent finishing. While agents are still in flight we render
// pulsing placeholders, so you literally watch dozens of agents run at once and
// then cascade to done (green = clean, red = found something).

import { useMemo } from "react";

interface AgentResult {
  agent: string;
  where: string;
  findings: number;
  errored: boolean;
}

interface SwarmState {
  total: number;
  pass: string;
  agents: AgentResult[];
  complete: boolean;
  active: boolean;
}

const DISPATCH_RE = /Dispatching swarm \(([^)]+)\):\s*(\d+) specialist probe agents/;
const AGENT_RE = /^\[(\w+Agent)\]\s+(.+?)\s+→\s+(.+)$/;

const META: Record<string, { icon: string; label: string }> = {
  HeadersAgent: { icon: "🛡️", label: "Headers" },
  CORSAgent: { icon: "🔗", label: "CORS" },
  TLSAgent: { icon: "🔒", label: "TLS" },
  ExposureAgent: { icon: "📂", label: "Exposure" },
  CVEAgent: { icon: "🐛", label: "CVE" },
  XSSAgent: { icon: "⚡", label: "XSS" },
  SQLiAgent: { icon: "💉", label: "SQLi" },
  RedirectAgent: { icon: "↪️", label: "Redirect" },
  CSRFAgent: { icon: "🎭", label: "CSRF" },
};

function parseSwarm(log: string[]): SwarmState {
  let total = 0;
  let pass = "";
  let agents: AgentResult[] = [];
  let complete = false;
  let active = false;

  for (const line of log) {
    const d = line.match(DISPATCH_RE);
    if (d) {
      pass = d[1];
      total = parseInt(d[2], 10);
      agents = []; // a new swarm round resets the grid
      complete = false;
      active = true;
      continue;
    }
    const a = line.match(AGENT_RE);
    if (a && active) {
      const result = a[3];
      const m = result.match(/(\d+)\s+finding/);
      agents.push({
        agent: a[1],
        where: a[2],
        findings: m ? parseInt(m[1], 10) : 0,
        errored: /error/i.test(result),
      });
      continue;
    }
    if (line.includes("[aggregate] Swarm complete")) complete = true;
  }
  return { total, pass, agents, complete, active: active && !complete };
}

function shortPath(url: string): string {
  try {
    const u = new URL(url);
    return (u.pathname === "/" ? u.host : u.pathname).slice(0, 18);
  } catch {
    return url.slice(0, 18);
  }
}

export default function SwarmView({ log }: { log: string[] }) {
  const swarm = useMemo(() => parseSwarm(log), [log]);
  if (!swarm.total && swarm.agents.length === 0) return null;

  const slots = Math.max(swarm.total, swarm.agents.length);
  const done = swarm.agents.length;
  const running = Math.max(0, slots - done);

  return (
    <div className="mb-6 overflow-hidden rounded-xl border border-[#1b2330] bg-[#0a0d13]">
      <div className="flex flex-wrap items-center gap-3 border-b border-[#161d28] bg-[#0c1018] px-4 py-2.5">
        <span className="text-sm font-semibold text-gray-100">🐝 Agent Swarm</span>
        <span className="text-xs text-gray-500">{swarm.pass || "probing"}</span>
        <span className="ml-auto flex items-center gap-3 text-xs">
          <span className="text-gray-400">
            <b className="text-gray-100">{slots}</b> dispatched
          </span>
          {running > 0 && (
            <span className="flex items-center gap-1.5 text-amber-400">
              <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-amber-400" />
              {running} running
            </span>
          )}
          <span className="text-emerald-400">{done} done</span>
        </span>
      </div>

      <div className="grid grid-cols-[repeat(auto-fill,minmax(110px,1fr))] gap-2 p-4">
        {Array.from({ length: slots }).map((_, i) => {
          const a = swarm.agents[i];
          if (!a) {
            // Still in flight — pulsing placeholder.
            return (
              <div
                key={`run-${i}`}
                className="swarm-tile flex items-center gap-2 rounded-lg border border-amber-900/40 bg-amber-950/10 px-2.5 py-2"
              >
                <span className="pulse-dot h-2 w-2 shrink-0 rounded-full bg-amber-400" />
                <span className="truncate text-[11px] text-amber-300/80">probing…</span>
              </div>
            );
          }
          const meta = META[a.agent] || { icon: "🔍", label: a.agent.replace("Agent", "") };
          const tone = a.errored
            ? "border-slate-800 bg-slate-900/40 text-slate-400"
            : a.findings > 0
            ? "border-red-900/50 bg-red-950/20 text-red-300"
            : "border-emerald-900/40 bg-emerald-950/15 text-emerald-300";
          return (
            <div
              key={`done-${i}`}
              className={`swarm-pop flex flex-col gap-0.5 rounded-lg border px-2.5 py-2 ${tone}`}
              style={{ animationDelay: `${Math.min(i, 50) * 22}ms` }}
              title={`${a.agent} · ${a.where}`}
            >
              <div className="flex items-center gap-1.5">
                <span className="text-sm leading-none">{meta.icon}</span>
                <span className="truncate text-[11px] font-semibold">{meta.label}</span>
                {a.findings > 0 && (
                  <span className="ml-auto rounded bg-red-900/60 px-1 text-[9px] font-bold text-red-200">
                    {a.findings}
                  </span>
                )}
              </div>
              <span className="truncate font-mono text-[9px] text-gray-600">{shortPath(a.where)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
