"use client";

import { useEffect, useState } from "react";
import * as api from "@/lib/api";
import { ApiError } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import { timeAgo } from "@/lib/ui";

export default function KeysPage() {
  const [keys, setKeys] = useState<api.ApiKeyInfo[]>([]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);

  const load = () => api.listKeys().then((r) => setKeys(r.keys)).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.createKey(name.trim() || "default");
      setNewKey(res.api_key);
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create key.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        subtitle="Authenticate programmatic access and CI/CD integrations."
      />
      <div className="px-8 py-6">
        <form onSubmit={create} className="flex flex-col gap-2 sm:flex-row">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Key name (e.g. ci-pipeline)"
            className="flex-1 rounded-xl border border-[#1b2330] bg-[#0a0d13] px-4 py-3 text-sm text-gray-100 outline-none focus:border-hive-accent"
          />
          <button
            disabled={busy}
            className="rounded-xl bg-hive-accent px-6 py-3 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:opacity-50"
          >
            Create key
          </button>
        </form>
        {error && (
          <div className="mt-3 rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {newKey && (
          <div className="mt-4 rounded-xl border border-hive-accent/40 bg-hive-accent/[0.05] p-4">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-100">
                New API key — copy it now, it won't be shown again.
              </span>
              <button onClick={() => setNewKey(null)} className="text-xs text-gray-500 hover:text-gray-300">
                ✕
              </button>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <code className="flex-1 break-all rounded bg-black/40 px-3 py-2 font-mono text-xs text-hive-accent">
                {newKey}
              </code>
              <button
                onClick={() => navigator.clipboard.writeText(newKey)}
                className="rounded-lg border border-[#1b2330] px-3 py-2 text-xs text-gray-300 hover:bg-white/5"
              >
                copy
              </button>
            </div>
          </div>
        )}

        <div className="mt-6 overflow-hidden rounded-xl border border-[#1b2330]">
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-4 border-b border-[#161d28] bg-[#0c1018] px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
            <span>Name</span>
            <span>Prefix</span>
            <span>Last used</span>
            <span className="text-right">Created</span>
          </div>
          {keys.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-gray-600">No keys yet.</div>
          ) : (
            keys.map((k) => (
              <div
                key={k.id}
                className="grid grid-cols-[1fr_auto_auto_auto] items-center gap-4 border-b border-[#11161f] px-4 py-3 text-sm last:border-0"
              >
                <span className="text-gray-200">
                  {k.name}
                  {k.revoked && (
                    <span className="ml-2 rounded bg-red-950/60 px-1.5 py-0.5 text-[10px] text-red-300">
                      revoked
                    </span>
                  )}
                </span>
                <code className="font-mono text-xs text-gray-500">rh_{k.prefix}…</code>
                <span className="text-xs text-gray-600">{k.last_used_at ? timeAgo(k.last_used_at) : "never"}</span>
                <span className="text-right text-xs text-gray-600">{timeAgo(k.created_at)}</span>
              </div>
            ))
          )}
        </div>

        <p className="mt-3 text-xs text-gray-600">
          Use a key with{" "}
          <code className="rounded bg-black/40 px-1.5 py-0.5">
            Authorization: Bearer rh_…
          </code>{" "}
          to drive scans from CI or scripts.
        </p>
      </div>
    </div>
  );
}
