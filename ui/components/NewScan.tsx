"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import * as api from "@/lib/api";
import { ApiError } from "@/lib/api";

// Launcher to start a new scan. Lets the user pick a verified target or type a
// URL against one. Enqueues and navigates to the scan detail page.
export default function NewScan() {
  const router = useRouter();
  const [targets, setTargets] = useState<api.Target[]>([]);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listTargets()
      .then((r) => {
        const verified = r.targets.filter((t) => t.verified);
        setTargets(verified);
        if (verified.length && !value) {
          const t = verified[0];
          setValue(t.host.includes("://") ? t.host : `http://${t.host}`);
        }
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function run() {
    if (!value.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const { scan_id } = await api.createScan(value.trim());
      router.push(`/scans/${scan_id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to start scan.");
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <span className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-600">
            ⌖
          </span>
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="https://app.yourcompany.com"
            disabled={busy}
            list="verified-targets"
            onKeyDown={(e) => e.key === "Enter" && !busy && run()}
            className="w-full rounded-xl border border-[#1b2330] bg-[#0a0d13] py-3 pl-9 pr-4 text-sm text-gray-100 outline-none transition focus:border-hive-accent disabled:opacity-60"
          />
          <datalist id="verified-targets">
            {targets.map((t) => (
              <option
                key={t.id}
                value={t.host.includes("://") ? t.host : `http://${t.host}`}
              />
            ))}
          </datalist>
        </div>
        <button
          onClick={run}
          disabled={busy || !value.trim()}
          className="rounded-xl bg-hive-accent px-7 py-3 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {busy ? "Starting…" : "Run scan"}
        </button>
      </div>

      {error && (
        <div className="mt-3 rounded-xl border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {error}
          {error.includes("registered") && (
            <>
              {" "}
              <Link href="/targets" className="font-medium underline">
                Add &amp; verify a target →
              </Link>
            </>
          )}
        </div>
      )}
      {targets.length === 0 && !error && (
        <p className="mt-2 text-xs text-gray-600">
          Scan a built-in practice target (e.g. <code>http://localhost:3000</code>),
          or{" "}
          <Link href="/targets" className="text-hive-accent hover:underline">
            verify your own domain
          </Link>
          .
        </p>
      )}
    </div>
  );
}
