"use client";

import { useEffect, useState } from "react";
import * as api from "@/lib/api";
import { ApiError } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import { timeAgo } from "@/lib/ui";

export default function IntegrationsPage() {
  const [items, setItems] = useState<api.GitHubIntegration[]>([]);
  const [repo, setRepo] = useState("");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const load = () =>
    api.listIntegrations().then((r) => setItems(r.integrations)).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  async function connect(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setOk(null);
    try {
      const res = await api.connectGitHub(repo.trim(), token.trim());
      setOk(`Connected ${res.integration.repo_full_name} (default branch ${res.integration.default_branch}).`);
      setRepo("");
      setToken("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to connect.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    await api.disconnectGitHub(id).catch(() => {});
    load();
  }

  return (
    <div>
      <PageHeader
        title="Integrations"
        subtitle="Connect a GitHub repo so RedHive can open remediation pull requests."
      />
      <div className="px-8 py-6">
        {/* Connect form */}
        <div className="rounded-xl border border-[#1b2330] bg-[#0c1018]/70 p-5">
          <div className="mb-3 flex items-center gap-2">
            <span className="text-lg">🐙</span>
            <h2 className="text-sm font-semibold text-gray-100">Connect a GitHub repository</h2>
          </div>
          <form onSubmit={connect} className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">Repository (owner/repo)</span>
              <input
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                placeholder="acme/web-app"
                className="w-full rounded-lg border border-[#1b2330] bg-[#0a0d13] px-3 py-2.5 text-sm text-gray-100 outline-none focus:border-hive-accent"
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-gray-400">
                Access token{" "}
                <span className="text-gray-600">(fine-grained PAT with Contents + Pull requests write)</span>
              </span>
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="github_pat_…"
                className="w-full rounded-lg border border-[#1b2330] bg-[#0a0d13] px-3 py-2.5 font-mono text-sm text-gray-100 outline-none focus:border-hive-accent"
              />
            </label>
            <button
              disabled={busy || !repo.trim() || !token.trim()}
              className="rounded-xl bg-hive-accent px-6 py-2.5 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:opacity-50"
            >
              {busy ? "Validating…" : "Connect repository"}
            </button>
          </form>
          <p className="mt-2 text-xs text-gray-600">
            The token is validated against GitHub and stored encrypted. It's used
            only to open PRs on the repos you connect.
          </p>
          {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
          {ok && <div className="mt-3 text-sm text-emerald-400">{ok}</div>}
        </div>

        {/* Connected repos */}
        <h3 className="mt-6 text-sm font-semibold uppercase tracking-wide text-gray-400">
          Connected repositories
        </h3>
        <div className="mt-3 overflow-hidden rounded-xl border border-[#1b2330]">
          {items.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-gray-600">
              No repositories connected yet.
            </div>
          ) : (
            items.map((i) => (
              <div
                key={i.id}
                className="flex items-center gap-3 border-b border-[#11161f] px-4 py-3 text-sm last:border-0"
              >
                <span className="text-base">🐙</span>
                <span className="font-mono text-gray-200">{i.repo_full_name}</span>
                <span className="rounded bg-[#1b2330] px-1.5 py-0.5 text-[10px] text-gray-400">
                  {i.default_branch}
                </span>
                <span className="ml-auto text-xs text-gray-600">{timeAgo(i.created_at)}</span>
                <button
                  onClick={() => remove(i.id)}
                  className="rounded-lg border border-[#1b2330] px-3 py-1.5 text-xs text-gray-400 hover:bg-white/5 hover:text-red-300"
                >
                  Disconnect
                </button>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
