"use client";

import { useEffect, useState } from "react";
import * as api from "@/lib/api";
import { ApiError } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import { timeAgo } from "@/lib/ui";

export default function TargetsPage() {
  const [targets, setTargets] = useState<api.Target[]>([]);
  const [host, setHost] = useState("");
  const [method, setMethod] = useState<"dns_txt" | "http_file">("dns_txt");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [instructions, setInstructions] = useState<{
    target: api.Target;
    v: api.VerificationInstructions;
  } | null>(null);

  const load = () => api.listTargets().then((r) => setTargets(r.targets)).catch(() => {});
  useEffect(() => {
    load();
  }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!host.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.createTarget(host.trim(), host.trim(), method);
      setHost("");
      await load();
      if (res.verification) setInstructions({ target: res.target, v: res.verification });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to add target.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Targets"
        subtitle="Register and verify the hosts you're authorized to scan."
      />
      <div className="px-8 py-6">
        {/* Add target */}
        <form onSubmit={add} className="flex flex-col gap-2 sm:flex-row">
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="app.yourcompany.com"
            className="flex-1 rounded-xl border border-[#1b2330] bg-[#0a0d13] px-4 py-3 text-sm text-gray-100 outline-none focus:border-hive-accent"
          />
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value as "dns_txt" | "http_file")}
            className="rounded-xl border border-[#1b2330] bg-[#0a0d13] px-3 py-3 text-sm text-gray-300 outline-none focus:border-hive-accent"
          >
            <option value="dns_txt">DNS TXT</option>
            <option value="http_file">HTTP file</option>
          </select>
          <button
            disabled={busy || !host.trim()}
            className="rounded-xl bg-hive-accent px-6 py-3 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:opacity-50"
          >
            Add target
          </button>
        </form>
        <p className="mt-2 text-xs text-gray-600">
          Practice hosts (<code>localhost</code>, <code>juiceshop</code>) are
          pre-verified. Your own domains require an ownership proof.
        </p>
        {error && (
          <div className="mt-3 rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {instructions && (
          <Instructions
            data={instructions}
            onClose={() => setInstructions(null)}
            onVerified={() => {
              setInstructions(null);
              load();
            }}
          />
        )}

        {/* Target list */}
        <div className="mt-6 overflow-hidden rounded-xl border border-[#1b2330]">
          {targets.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-gray-600">
              No targets yet.
            </div>
          ) : (
            targets.map((t) => (
              <TargetRow key={t.id} target={t} onChange={load} onShow={setInstructions} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function TargetRow({
  target,
  onChange,
  onShow,
}: {
  target: api.Target;
  onChange: () => void;
  onShow: (d: { target: api.Target; v: api.VerificationInstructions }) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function verify() {
    setBusy(true);
    setErr(null);
    try {
      await api.verifyTarget(target.id);
      onChange();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="border-b border-[#11161f] px-4 py-3 last:border-0">
      <div className="flex items-center gap-3">
        <span className="font-mono text-sm text-gray-200">{target.host}</span>
        {target.verified ? (
          <span className="rounded-full bg-emerald-950/60 px-2 py-0.5 text-[10px] font-medium text-emerald-300">
            ✓ verified
          </span>
        ) : (
          <span className="rounded-full bg-amber-950/60 px-2 py-0.5 text-[10px] font-medium text-amber-300">
            ○ unverified
          </span>
        )}
        <span className="rounded bg-[#1b2330] px-1.5 py-0.5 text-[10px] uppercase text-gray-500">
          {target.method}
        </span>
        <span className="ml-auto text-xs text-gray-600">{timeAgo(target.created_at)}</span>
        {!target.verified && target.method !== "practice" && (
          <>
            <button
              onClick={() =>
                onShow({
                  target,
                  v: {
                    method: target.method,
                    record_name: `_redhive-verify.${target.host}`,
                    record_type: "TXT",
                    record_value: target.verification_token,
                    url: `https://${target.host}/.well-known/redhive-verify.txt`,
                    file_contents: target.verification_token,
                    hint: "Publish the token below, then click Verify.",
                  },
                })
              }
              className="rounded-lg border border-[#1b2330] px-3 py-1.5 text-xs text-gray-300 hover:bg-white/5"
            >
              Instructions
            </button>
            <button
              onClick={verify}
              disabled={busy}
              className="rounded-lg bg-hive-accent px-3 py-1.5 text-xs font-semibold text-black hover:bg-amber-400 disabled:opacity-50"
            >
              {busy ? "Checking…" : "Verify"}
            </button>
          </>
        )}
      </div>
      {err && <div className="mt-2 text-xs text-red-400">{err}</div>}
    </div>
  );
}

function Instructions({
  data,
  onClose,
  onVerified,
}: {
  data: { target: api.Target; v: api.VerificationInstructions };
  onClose: () => void;
  onVerified: () => void;
}) {
  const { target, v } = data;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const dns = v.method === "dns_txt";

  async function verify() {
    setBusy(true);
    setErr(null);
    try {
      await api.verifyTarget(target.id);
      onVerified();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Verification failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-4 rounded-xl border border-hive-accent/30 bg-hive-accent/[0.04] p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-100">
          Verify ownership of <span className="font-mono">{target.host}</span>
        </h3>
        <button onClick={onClose} className="text-xs text-gray-500 hover:text-gray-300">
          ✕
        </button>
      </div>
      <p className="mt-1 text-xs text-gray-400">{v.hint}</p>

      <div className="mt-3 space-y-2 text-sm">
        {dns ? (
          <Row label="TXT record" value={v.record_name || ""} />
        ) : (
          <Row label="File URL" value={v.url || ""} />
        )}
        <Row label={dns ? "Value" : "Contents"} value={(dns ? v.record_value : v.file_contents) || ""} />
      </div>

      {err && <div className="mt-2 text-xs text-red-400">{err}</div>}
      <button
        onClick={verify}
        disabled={busy}
        className="mt-3 rounded-lg bg-hive-accent px-4 py-2 text-xs font-semibold text-black hover:bg-amber-400 disabled:opacity-50"
      >
        {busy ? "Checking…" : "I've published it — Verify"}
      </button>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="w-24 shrink-0 text-xs text-gray-500">{label}</span>
      <code className="flex-1 break-all rounded bg-black/40 px-2 py-1 font-mono text-[11px] text-hive-accent">
        {value}
      </code>
      <button
        onClick={() => navigator.clipboard.writeText(value)}
        className="text-xs text-gray-500 hover:text-gray-300"
      >
        copy
      </button>
    </div>
  );
}
