// Thin client for the RedHive FastAPI backend.

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  title: string;
  category: string;
  severity: Severity;
  target: string;
  description?: string;
  evidence?: string;
  reproduction?: string[];
  remediation?: string;
}

export interface Scan {
  scan_id: string;
  target: string;
  status: "pending" | "running" | "done" | "failed" | string;
  findings: Finding[];
  log: string[];
}

export async function startScan(target: string): Promise<{ scan_id: string }> {
  const res = await fetch(`${API_URL}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  if (res.status === 403) {
    throw new Error(
      "Target is not on the allowlist. RedHive only scans authorized practice targets."
    );
  }
  if (!res.ok) throw new Error(`Failed to start scan (HTTP ${res.status})`);
  return res.json();
}

export async function getScan(scanId: string): Promise<Scan> {
  const res = await fetch(`${API_URL}/scans/${scanId}`);
  if (!res.ok) throw new Error(`Failed to fetch scan (HTTP ${res.status})`);
  return res.json();
}

// Subscribe to the live log via Server-Sent Events. Returns an unsubscribe fn.
export function streamLog(
  scanId: string,
  onLine: (line: string) => void,
  onDone: () => void
): () => void {
  const es = new EventSource(`${API_URL}/scans/${scanId}/log`);
  es.addEventListener("log", (e) => onLine((e as MessageEvent).data));
  es.addEventListener("done", () => {
    es.close();
    onDone();
  });
  es.onerror = () => {
    es.close();
    onDone();
  };
  return () => es.close();
}
