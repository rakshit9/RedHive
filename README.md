# RedHive

> Autonomous multi-agent pentest platform — point a team of AI agents at a target and get back proof-backed vulnerabilities with reproduction steps and fixes.

RedHive runs a coordinated team of LLM-driven agents that recon a web target, plan attacks, execute safe checks, validate the results, and write up findings — the way a human red team would, but automated end to end. It mirrors the approach of [MindFort](https://mindfort.ai): every finding ships with **proof of exploit, reproduction steps, and remediation**, not just a noisy scanner alert.

---

## ⚠️ Authorized use only

**RedHive is a security tool. Only ever point it at systems you own or are explicitly authorized to test.**

- Out of the box it only scans practice targets on a strict allowlist — [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) and `localhost`.
- Every agent and tool routes through a single scope guard (`redhive/scope.py`). A target whose host is not in `SCAN_ALLOWLIST` is **refused before a single packet is sent** — the API returns `403`.
- Do **not** add hosts you do not own to `SCAN_ALLOWLIST`. Scanning systems without authorization is illegal in most jurisdictions.

---

## What it does

Give RedHive a target URL and it will:

1. **Recon** the attack surface — discover endpoints, forms, and parameters.
2. **Plan** an engagement — the Lead agent decides what to probe based on the fingerprint.
3. **Test** for common web vulnerabilities — security headers, TLS misconfig, exposed files, reflected XSS.
4. **Validate** each candidate to weed out false positives.
5. **Report** confirmed findings with evidence, repro steps, and an LLM-written fix.

Results stream live over Server-Sent Events and persist to Postgres.

---

## Architecture

RedHive is a [LangGraph](https://langchain-ai.github.io/langgraph/) state machine over a shared `EngagementState` contract. Each agent reads what it needs from the state and writes its results back.

```
            ┌──────────────┐
   target ─▶│ Orchestrator │── out of scope ──▶ END
            └──────┬───────┘
                   │ in scope
                   ▼
   ┌────────┐   ┌──────┐   ┌────────┐   ┌───────────┐   ┌──────────┐
   │ Recon  │─▶ │ Lead │─▶ │ Tester │─▶ │ Validator │─▶ │ Reporter │─▶ findings
   └────────┘   └──────┘   └────────┘   └───────────┘   └──────────┘
```

| Agent          | Responsibility                                                        |
| -------------- | --------------------------------------------------------------------- |
| **Orchestrator** | Enforces scope; halts the run immediately if the target is off-list. |
| **Recon**      | Maps attack surface (endpoints, forms, params) and fingerprints the stack. |
| **Lead**       | Reasons over the fingerprint and builds the test plan.                |
| **Tester**     | Executes the safe vulnerability checks and produces candidate findings. |
| **Validator**  | Confirms or discards each candidate to minimize false positives.      |
| **Reporter**   | Writes human-readable findings with evidence and remediation.         |

**Provider-flexible LLM.** Every agent's brain is swappable. OpenAI (`gpt-4o`) is the default; set `LLM_PROVIDER=claude` to run the team on Anthropic Claude instead — no code changes.

---

## Tech stack

| Layer            | Technology                                  |
| ---------------- | ------------------------------------------- |
| Agent orchestration | [LangGraph](https://langchain-ai.github.io/langgraph/) |
| API              | [FastAPI](https://fastapi.tiangolo.com/) + [sse-starlette](https://github.com/sysid/sse-starlette) (live log streaming) |
| Persistence      | [PostgreSQL](https://www.postgresql.org/) via SQLAlchemy 2.0 |
| Infra            | [Docker Compose](https://docs.docker.com/compose/) (Juice Shop + Postgres) |
| HTTP scanning    | [httpx](https://www.python-httpx.org/) + BeautifulSoup |

---

## Quickstart

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# edit .env and set your key:
#   OPENAI_API_KEY=sk-...
```

### 3. Start the practice target + database

```bash
docker compose up -d   # starts OWASP Juice Shop (port 3000) and Postgres (5432)
```

### 4. Run the API

```bash
uvicorn redhive.api.app:app --reload
# API on http://localhost:8000  (docs at /docs)
```

### 5. Kick off a scan

```bash
# Start a scan against the local Juice Shop
curl -s -X POST http://localhost:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"target": "http://localhost:3000"}'
# -> {"scan_id": "...", "status": "running"}

# Poll status + findings
curl -s http://localhost:8000/scans/<scan_id>

# (Optional) follow the live agent log over SSE
curl -N http://localhost:8000/scans/<scan_id>/log
```

A target outside the allowlist is rejected up front:

```bash
curl -s -X POST http://localhost:8000/scans \
  -H 'Content-Type: application/json' \
  -d '{"target": "http://example.com"}'
# -> 403  "Target ... is not in the scan allowlist ... Refusing to scan unauthorized targets."
```

### API endpoints

| Method | Path                   | Description                                          |
| ------ | ---------------------- | ---------------------------------------------------- |
| `POST` | `/scans`               | Start a scan. Body: `{"target": "..."}`. Returns `{scan_id, status}`. `403` if out of scope. |
| `GET`  | `/scans/{scan_id}`     | Status, findings, and accumulated log for a scan.    |
| `GET`  | `/scans/{scan_id}/log` | Live agent log as Server-Sent Events; closes when the scan finishes. |
| `GET`  | `/healthz`             | Liveness probe.                                      |

---

## Project status / roadmap

**MVP (now)** — working end-to-end engagement with these checks:

- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- TLS / HTTPS misconfiguration
- Exposed sensitive files
- Reflected XSS

**Roadmap**

- Authenticated scanning (login flows, session reuse)
- Auto-patch PRs — turn each finding into a suggested code fix and open a pull request
- Continuous scheduling — recurring scans with diffing and alerting
- Broader check library (SQLi, IDOR, SSRF) and richer exploit chaining
