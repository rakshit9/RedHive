import type { AttackChain, Patch } from "@/lib/api";

export function AttackChainCard({ chain }: { chain: AttackChain }) {
  return (
    <div className="rounded-xl border border-fuchsia-900/40 bg-fuchsia-950/10 p-4">
      <div className="flex items-center gap-2 text-sm font-semibold text-fuchsia-300">
        <span>⚔️</span>
        {chain.name}
      </div>
      <ol className="mt-2 space-y-1.5">
        {chain.steps.map((step, i) => (
          <li key={i} className="flex gap-2 text-sm text-gray-300">
            <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-fuchsia-900/50 text-[10px] text-fuchsia-200">
              {i + 1}
            </span>
            {step}
          </li>
        ))}
      </ol>
      {chain.impact && (
        <div className="mt-2 border-t border-fuchsia-900/30 pt-2 text-xs text-gray-400">
          <span className="font-semibold text-fuchsia-300">Impact: </span>
          {chain.impact}
        </div>
      )}
    </div>
  );
}

export function PatchCard({ patch }: { patch: Patch }) {
  return (
    <div className="overflow-hidden rounded-xl border border-orange-900/40 bg-orange-950/10">
      <div className="border-b border-orange-900/30 px-4 py-2.5">
        <div className="flex items-center gap-2 text-sm font-semibold text-orange-300">
          <span>🔧</span>
          {patch.finding_title}
        </div>
        {patch.file_hint && (
          <div className="mt-0.5 font-mono text-[11px] text-gray-500">
            {patch.file_hint}
          </div>
        )}
      </div>
      {patch.diff && (
        <pre className="overflow-x-auto bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-gray-300">
          {patch.diff}
        </pre>
      )}
    </div>
  );
}
