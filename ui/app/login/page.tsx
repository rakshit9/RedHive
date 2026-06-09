"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";

export default function LoginPage() {
  const { ready, authed, login, signup } = useAuth();
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);

  useEffect(() => {
    if (ready && authed && !newKey) router.replace("/");
  }, [ready, authed, router, newKey]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "login") {
        await login(email.trim(), password);
      } else {
        const res = await signup(org.trim(), email.trim(), password);
        // Show the one-time API key before navigating away.
        if (res.api_key) {
          setNewKey(res.api_key);
          return;
        }
        router.push("/");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  }

  if (newKey) {
    return (
      <Shell>
        <h1 className="text-xl font-semibold text-gray-100">You're in. 🎉</h1>
        <p className="mt-1 text-sm text-gray-400">
          Here is your API key. Copy it now — it won't be shown again.
        </p>
        <div className="mt-4 break-all rounded-lg border border-hive-accent/40 bg-black/40 p-3 font-mono text-xs text-hive-accent">
          {newKey}
        </div>
        <button
          onClick={() => navigator.clipboard.writeText(newKey)}
          className="mt-3 rounded-lg border border-[#1b2330] px-3 py-2 text-xs text-gray-300 hover:bg-white/5"
        >
          Copy key
        </button>
        <button
          onClick={() => router.push("/")}
          className="mt-4 w-full rounded-xl bg-hive-accent px-4 py-3 text-sm font-semibold text-black transition hover:bg-amber-400"
        >
          Go to dashboard →
        </button>
      </Shell>
    );
  }

  return (
    <Shell>
      <div className="mb-6 text-center">
        <div className="mb-2 text-3xl">🐝</div>
        <h1 className="text-xl font-bold tracking-tight text-gray-100">
          Red<span className="text-hive-accent">Hive</span>
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          {mode === "login"
            ? "Sign in to your security workspace."
            : "Create your security workspace."}
        </p>
      </div>

      <form onSubmit={submit} className="space-y-3">
        {mode === "signup" && (
          <Field
            label="Organization"
            value={org}
            onChange={setOrg}
            placeholder="Acme Security"
            required
          />
        )}
        <Field
          label="Email"
          type="email"
          value={email}
          onChange={setEmail}
          placeholder="you@company.com"
          required
        />
        <Field
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          placeholder="••••••••"
          required
        />

        {error && (
          <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-3 py-2 text-xs text-red-300">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-xl bg-hive-accent px-4 py-3 text-sm font-semibold text-black transition hover:bg-amber-400 disabled:opacity-50"
        >
          {busy ? "…" : mode === "login" ? "Sign in" : "Create workspace"}
        </button>
      </form>

      <div className="mt-5 text-center text-xs text-gray-500">
        {mode === "login" ? "New to RedHive?" : "Already have an account?"}{" "}
        <button
          onClick={() => {
            setMode(mode === "login" ? "signup" : "login");
            setError(null);
          }}
          className="font-medium text-hive-accent hover:underline"
        >
          {mode === "login" ? "Create a workspace" : "Sign in"}
        </button>
      </div>
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-2xl border border-[#1b2330] bg-[#0c1018]/80 p-7 shadow-2xl backdrop-blur">
        {children}
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  required,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-gray-400">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        className="w-full rounded-lg border border-[#1b2330] bg-[#0a0d13] px-3 py-2.5 text-sm text-gray-100 outline-none transition focus:border-hive-accent"
      />
    </label>
  );
}
