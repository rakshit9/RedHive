"use client";

// Visualizes the multi-agent pipeline, lighting up stages as the scan runs.

const STAGES = [
  { key: "manager", label: "Orchestrator", icon: "🛡️" },
  { key: "recon", label: "Recon", icon: "🔍" },
  { key: "lead", label: "Lead", icon: "🧠" },
  { key: "tester", label: "Tester", icon: "💥" },
  { key: "validator", label: "Validator", icon: "✅" },
  { key: "reporter", label: "Reporter", icon: "📝" },
] as const;

type StageState = "pending" | "active" | "done";

function stageStates(log: string[], finished: boolean): Record<string, StageState> {
  // Find the latest stage mentioned in the log.
  let latestIdx = -1;
  for (const line of log) {
    STAGES.forEach((s, i) => {
      if (line.includes(`[${s.key}]`) && i > latestIdx) latestIdx = i;
    });
  }
  const states: Record<string, StageState> = {};
  STAGES.forEach((s, i) => {
    if (latestIdx === -1) states[s.key] = "pending";
    else if (finished) states[s.key] = i <= latestIdx ? "done" : "pending";
    else if (i < latestIdx) states[s.key] = "done";
    else if (i === latestIdx) states[s.key] = "active";
    else states[s.key] = "pending";
  });
  return states;
}

export default function Pipeline({
  log,
  finished,
}: {
  log: string[];
  finished: boolean;
}) {
  const states = stageStates(log, finished);

  return (
    <div className="flex items-center gap-1.5 overflow-x-auto rounded-xl border border-[#1b2330] bg-[#0c1018]/70 px-3 py-3">
      {STAGES.map((s, i) => {
        const st = states[s.key];
        const color =
          st === "done"
            ? "border-emerald-700/60 bg-emerald-950/40 text-emerald-300"
            : st === "active"
            ? "border-amber-500/70 bg-amber-950/40 text-amber-300 glow-amber"
            : "border-[#1b2330] bg-[#0c1018] text-gray-600";
        return (
          <div key={s.key} className="flex items-center gap-1.5">
            <div
              className={`flex shrink-0 items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium transition ${color}`}
            >
              <span className={st === "active" ? "pulse-dot" : ""}>{s.icon}</span>
              <span>{s.label}</span>
            </div>
            {i < STAGES.length - 1 && (
              <div
                className={`h-px w-4 shrink-0 ${
                  states[STAGES[i + 1].key] !== "pending"
                    ? "bg-emerald-700/50"
                    : "bg-[#1b2330]"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
