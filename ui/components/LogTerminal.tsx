"use client";

import { useEffect, useRef } from "react";
import { logLineColor } from "@/lib/ui";

export default function LogTerminal({
  log,
  live,
}: {
  log: string[];
  live: boolean;
}) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [log]);

  return (
    <div className="overflow-hidden rounded-xl border border-[#1b2330] bg-[#0a0d13]">
      <div className="flex items-center gap-2 border-b border-[#161d28] bg-[#0c1018] px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
        <span className="ml-2 text-xs text-gray-500">agent log</span>
        {live && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-amber-400">
            <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-amber-400" />
            live
          </span>
        )}
      </div>
      <div className="log-scroll h-[520px] overflow-y-auto p-4 font-mono text-xs leading-relaxed">
        {log.length === 0 ? (
          <span className="text-gray-600">$ waiting for the agents to start…</span>
        ) : (
          log.map((line, i) => (
            <div key={i} className={`fade-in ${logLineColor(line)}`}>
              <span className="select-none text-gray-700">›</span> {line}
            </div>
          ))
        )}
        <div ref={endRef} />
      </div>
    </div>
  );
}
