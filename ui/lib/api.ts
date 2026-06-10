// Typed, authenticated client for the RedHive API.
//
// The session token is held in localStorage (see lib/auth.tsx) and attached as
// a Bearer header on every request. The live log uses fetch + ReadableStream
// (not EventSource) so it can send the Authorization header too.

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TOKEN_KEY = "redhive_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(TOKEN_KEY, token);
  else window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  opts: { method?: string; body?: unknown; auth?: boolean } = {}
): Promise<T> {
  const { method = "GET", body, auth = true } = opts;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      detail = data.detail || detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// --------------------------------------------------------------------------- //
// Types                                                                       //
// --------------------------------------------------------------------------- //

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "queued" | "running" | "done" | "failed" | "canceled";
export type Regression = "new" | "recurring" | "fixed";

export interface Finding {
  id?: string;
  title: string;
  category: string;
  severity: Severity;
  target: string;
  description?: string;
  evidence?: string;
  reproduction?: string[];
  remediation?: string;
  confirmed?: boolean;
  discovered_by?: string;
  regression?: Regression;
}

export interface AttackChain {
  name: string;
  steps: string[];
  impact: string;
}

export interface Patch {
  finding_title: string;
  file_hint: string;
  diff: string;
  explanation: string;
}

export interface ScanSummary {
  scan_id: string;
  target: string;
  status: ScanStatus;
  risk_score: number | null;
  severity_counts: Record<string, number>;
  findings_count: number;
  regression_summary: { new: number; recurring: number; fixed: number } | null;
  created_at: string | null;
  finished_at: string | null;
}

export interface ScanDetail extends ScanSummary {
  findings: Finding[];
  patches: Patch[];
  attack_chains: AttackChain[];
  error: string;
  log: string[];
}

export interface Target {
  id: string;
  host: string;
  display_name: string;
  method: "dns_txt" | "http_file" | "practice";
  verification_token: string;
  verified: boolean;
  verified_at: string | null;
  created_at: string | null;
}

export interface VerificationInstructions {
  method: string;
  record_name?: string;
  record_type?: string;
  record_value?: string;
  url?: string;
  file_contents?: string;
  hint: string;
}

export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  created_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
}

// --------------------------------------------------------------------------- //
// Auth                                                                        //
// --------------------------------------------------------------------------- //

export interface AuthResult {
  token: string;
  org_id: string;
  api_key?: string;
}

export function signup(org_name: string, email: string, password: string) {
  return request<AuthResult>("/auth/signup", {
    method: "POST",
    body: { org_name, email, password },
    auth: false,
  });
}

export function login(email: string, password: string) {
  return request<AuthResult>("/auth/login", {
    method: "POST",
    body: { email, password },
    auth: false,
  });
}

export interface Me {
  org_id: string;
  org_name: string;
  plan: string;
  email: string;
}

export function me() {
  return request<Me>("/auth/me");
}

export function listKeys() {
  return request<{ keys: ApiKeyInfo[] }>("/auth/keys");
}

export function createKey(name: string) {
  return request<{ id: string; name: string; prefix: string; api_key: string }>(
    "/auth/keys",
    { method: "POST", body: { name } }
  );
}

// --------------------------------------------------------------------------- //
// Targets                                                                     //
// --------------------------------------------------------------------------- //

export function listTargets() {
  return request<{ targets: Target[] }>("/targets");
}

export function createTarget(
  host: string,
  display_name: string,
  method: "dns_txt" | "http_file"
) {
  return request<{
    target: Target;
    verification: VerificationInstructions | null;
    message: string;
  }>("/targets", { method: "POST", body: { host, display_name, method } });
}

export function verifyTarget(id: string) {
  return request<{ verified: boolean; target: Target }>(
    `/targets/${id}/verify`,
    { method: "POST" }
  );
}

// --------------------------------------------------------------------------- //
// Scans                                                                       //
// --------------------------------------------------------------------------- //

export function listScans(limit = 50) {
  return request<{ scans: ScanSummary[] }>(`/scans?limit=${limit}`);
}

export function createScan(target: string) {
  return request<{ scan_id: string; status: string }>("/scans", {
    method: "POST",
    body: { target },
  });
}

export function getScan(scanId: string) {
  return request<ScanDetail>(`/scans/${scanId}`);
}

export function reportUrl(scanId: string, format: "markdown" | "json") {
  return `${API_URL}/scans/${scanId}/report?format=${format}`;
}

export function openPullRequest(scanId: string) {
  return request<{ pr_url: string; branch: string; repo: string }>(
    `/scans/${scanId}/pr`,
    { method: "POST" }
  );
}

// --------------------------------------------------------------------------- //
// GitHub integrations                                                         //
// --------------------------------------------------------------------------- //

export interface GitHubIntegration {
  id: string;
  repo_full_name: string;
  default_branch: string;
  created_at: string | null;
}

export function listIntegrations() {
  return request<{ integrations: GitHubIntegration[] }>("/integrations/github");
}

export function connectGitHub(repo_full_name: string, token: string) {
  return request<{ integration: GitHubIntegration; message: string }>(
    "/integrations/github",
    { method: "POST", body: { repo_full_name, token } }
  );
}

export function disconnectGitHub(id: string) {
  return request<void>(`/integrations/github/${id}`, { method: "DELETE" });
}

// Stream the live log via fetch + ReadableStream so we can pass the auth header
// (EventSource cannot). Parses the SSE wire format manually. Returns an abort fn.
export function streamLog(
  scanId: string,
  onLine: (line: string) => void,
  onDone: (status: string) => void
): () => void {
  const controller = new AbortController();
  const token = getToken();

  (async () => {
    try {
      const res = await fetch(`${API_URL}/scans/${scanId}/log`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        onDone("failed");
        return;
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let event = "message";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n");
        buffer = chunks.pop() ?? "";
        for (const raw of chunks) {
          const line = raw.replace(/\r$/, "");
          if (line.startsWith("event:")) {
            event = line.slice(6).trim();
          } else if (line.startsWith("data:")) {
            const data = line.slice(5).replace(/^ /, "");
            if (event === "done") onDone(data);
            else onLine(data);
          } else if (line === "") {
            event = "message";
          }
        }
      }
    } catch {
      if (!controller.signal.aborted) onDone("failed");
    }
  })();

  return () => controller.abort();
}
