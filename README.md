<div align="center">

# 🐝 RedHive

### Autonomous multi-agent penetration testing — find, prove, and **fix** vulnerabilities, end to end.

Point a team of AI agents at a web target. They map the attack surface, dispatch a **parallel swarm of specialist agents** to test it, validate every finding to kill false positives, write up proof + reproduction + remediation, and open a **GitHub pull request** with the fix.

[Architecture](#-architecture) · [Quickstart](#-quickstart) · [How it works](#-how-an-engagement-runs) · [The numbers](#-the-numbers-measured) · [API](#-api)

</div>

---

## ⚠️ Authorized use only

**RedHive is offensive security tooling. Only ever point it at systems you own or are explicitly authorized to test.**

Every agent and tool routes through a single scope guard (`redhive/scope.py`). A target is refused **before a single packet is sent** unless it is either a built-in practice host **or** a domain the organization has **proven it owns** (DNS TXT / HTTP file verification). Out of the box only practice targets are in scope — the bundled vulnerable demo app, `localhost`, and OWASP Juice Shop. Scanning systems without authorization is illegal in most jurisdictions.

---

## What it is

RedHive is a working, multi-tenant SaaS implementation of the emerging **"autonomous pentest"** category — the same product space as [MindFort](https://www.mindfort.ai), XBOW, and Horizon3.ai. The thesis: software ships faster than security teams can review it, so security testing has to become **continuous, autonomous, and self-remediating**.

It does the full loop a human red team would, automated:

> **recon → plan → exploit (parallel swarm) → validate → report → patch → open PR**

…and it gets smarter on every re-scan (it remembers prior findings and reports what's **new / recurring / fixed**).

## ✨ Highlights

| | |
|---|---|
| 🧠 **Hierarchical multi-agent system** | A LangGraph state machine: an LLM **Lead** plans, a swarm executes, an LLM **Validator** triages, and Reporter / Patch / Strategist agents finish the job. |
| ⚡ **Parallel agent swarm** | The Lead fans out **one specialist agent per (endpoint × vulnerability class)** via LangGraph's `Send` map-reduce — **dozens of agents run concurrently** (measured: 50–115 per scan, ~10× faster than sequential). |
| 🛡️ **Proof-backed findings** | Each finding ships with evidence, reproduction steps, and an LLM-written remediation — validated to keep false positives low. |
| ⚔️ **Exploit chaining + risk score** | A Strategist agent reasons about how findings chain into real attack paths and computes a 0–100 risk score. |
| 🔧 **Auto-remediation → GitHub PRs** | Drafts fixes for the top findings and opens a real pull request on a connected repo (token encrypted at rest). |
| 🧗 **HillClimb memory** | Cross-scan diffing tags findings `new` / `recurring` / `fixed` so the platform gets more useful the more it runs. |
| 🔐 **Multi-tenant from day one** | Orgs, users, API keys, per-org **domain-ownership verification**, plan quotas. |
| 💸 **Token + cost tracking** | Every scan reports exactly how many LLM tokens it used and the estimated USD cost. |
| 🏗️ **Built to scale** | API only *enqueues*; a separate worker pool pulls jobs from a Postgres queue (`FOR UPDATE SKIP LOCKED`) — add workers to scale horizontally. |

## 🖥️ Dashboard

A Next.js dashboard with live scanning: a **real-time agent-swarm visualizer** (watch the agents light up and resolve in parallel), risk gauge, expandable findings, attack-chain and patch-diff views, target/ownership management, API keys, and GitHub integration.

> _Add a 2-minute Loom and screenshots here — the swarm visualizer and a finished report are the money shots._

---

## 🏛️ Architecture

```
                    ┌──────────────┐   out of scope
        target ────▶│ Orchestrator │──────────────▶ END
                    └──────┬───────┘
                           │ in scope
                           ▼
   ┌────────┐   ┌──────┐   ┌─────────────┐   ══ Send × N ══▶  ┌───────┐
   │ Recon  │──▶│ Lead │──▶│ plan_probes │ ─────────────────▶ │ probe │ ┐
   └────────┘   └──────┘   └─────────────┘                    │ probe │ ┤ (parallel
   crawl +      LLM plan   fan out one agent per              │ probe │ ┘  swarm,
   path-disc.              (endpoint × vuln class)             └───┬───┘    ≤12 concurrent)
                                                                   ▼ reduce
   ┌───────────┐   ┌───────────┐   ┌───────────┐           ┌───────────┐
   │ Strategist│◀──│   Patch   │◀──│  Reporter │◀── finish ─│ lead_review│◀── ┌───────────┐
   │ chains +  │   │ fixes +   │   │ remediation│   ▲ loop  └───────────┘     │ aggregate │
   │ risk score│   │ GitHub PR │   └───────────┘   │ deepen        ▲          └─────┬─────┘
   └─────┬─────┘   └───────────┘                   └───────────────┘                │
         ▼                                                  ┌───────────┐           │
        END                                                 │ Validator │◀──────────┘
                                                            └───────────┘ confirm / dedupe
```

**The testing phase is a map-reduce swarm.** `plan_probes` expands the attack surface into N tasks; `fan_out_probes` emits a LangGraph `Send` per task so the probe agents (HeadersAgent, XSSAgent, SQLiAgent, TLSAgent, CVEAgent, …) run **concurrently in one super-step**; results merge through an `operator.add` reducer channel; `aggregate` fans them back in. A semaphore bounds how many hit the target at once. The probe swarm uses **zero LLM tokens** — only the orchestration agents (Lead, Validator, Reporter, Patch, Strategist) call the model — so cost scales with *findings*, not with scan size.

## 🔁 How an engagement runs

1. **Recon** — crawl the target *and* probe a wordlist of common paths to map a wide attack surface; fingerprint the stack.
2. **Lead (LLM)** — reason over the surface and decide what to test.
3. **Swarm** — dispatch a specialist agent per (endpoint × check), all in parallel.
4. **Validator** — confirm real findings, collapse duplicates / site-wide issues.
5. **Lead review (LLM)** — decide whether to loop for a deeper pass (wider coverage) or finish.
6. **Reporter (LLM)** — write actionable remediation per finding.
7. **Patch (LLM)** — draft fixes for the top findings; optionally open a GitHub PR.
8. **Strategist (LLM)** — chain findings into attack paths and score overall risk.

Results stream live over SSE and persist to Postgres; re-scans diff against history (HillClimb).

## 🧱 Tech stack

| Layer | Tech |
|---|---|
| Agent orchestration | **LangGraph** + LangChain (provider-flexible: OpenAI **or** Anthropic Claude) |
| API | **FastAPI** + SSE, API-key & session auth, multi-tenant |
| Persistence | **PostgreSQL** + SQLAlchemy 2.0 ORM + **Alembic** migrations |
| Worker | Postgres-backed job queue (`FOR UPDATE SKIP LOCKED`) |
| Frontend | **Next.js** (App Router) + Tailwind |
| Infra | **Docker Compose**; CI via GitHub Actions |
| Scanning | httpx + BeautifulSoup |

---

## 🚀 Quickstart

**Prereqs:** Python 3.12+, Node 18+, a reachable Postgres, and an LLM key.

```bash
# 1. Install
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cd ui && npm install && cd ..

# 2. Configure
cp .env.example .env        # set OPENAI_API_KEY (or LLM_PROVIDER=claude + ANTHROPIC_API_KEY)

# 3. Boot everything with one command
make dev          # or: ./scripts/dev.sh
```

That starts the **API** (`:8000`), a **worker**, the **dashboard** (`:3000`), and the bundled **vulnerable demo target** (`:8780`), and applies migrations.

Then open **http://localhost:3000**, sign up, and scan **`http://localhost:8780`** — you'll watch ~50 agents fan out in parallel and get back ~28 findings (XSS, SQLi, exposed `.env`, missing headers…), attack chains, and suggested fixes.

### Everything in Docker

```bash
docker compose up -d --build   # db + api (migrates on start) + worker + demo-target + juiceshop
```

### Drive it from the API

```bash
# Sign up -> session token + a one-time API key
curl -s -X POST localhost:8000/auth/signup -H 'content-type: application/json' \
  -d '{"org_name":"Acme","email":"you@acme.com","password":"password123"}'

# Enqueue a scan
curl -s -X POST localhost:8000/scans -H "authorization: Bearer rh_..." \
  -H 'content-type: application/json' -d '{"target":"http://localhost:8780"}'

# Follow the live agent log (SSE), then read results
curl -N localhost:8000/scans/<id>/log -H "authorization: Bearer rh_..."
```

---

## 📊 The numbers (measured)

A real scan of the bundled demo target (`make dev` → scan `http://localhost:8780`):

| Metric | Value |
|---|---|
| Parallel agents dispatched | **115** (across two passes) |
| Confirmed findings | **28** (17 high, 8 medium, 2 low, 1 info) |
| Attack chains | **3** |
| Suggested patches | **6** |
| LLM tokens | **10,655** across 37 calls |
| Estimated cost | **~$0.05** |

The swarm is ~10× faster than running the checks sequentially, and because only the orchestration agents use the LLM, a scan costs **cents** regardless of how many endpoints/agents it ran.

## 🔌 API

All endpoints are scoped to the authenticated org.

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/signup` · `/auth/login` | Create org + owner / log in; returns a session token (+ one-time API key on signup). |
| `GET`/`POST` | `/auth/keys` | List / mint API keys. |
| `GET`/`POST` | `/targets` · `POST /targets/{id}/verify` | Register a target; prove ownership (DNS/HTTP). |
| `POST` | `/scans` | Enqueue a scan (403 unless practice or verified target). |
| `GET` | `/scans` · `/scans/{id}` | List / full detail (findings, chains, patches, usage, log). |
| `GET` | `/scans/{id}/log` | Live agent log (SSE). |
| `GET` | `/scans/{id}/report` | Export report (`?format=markdown\|json`). |
| `POST` | `/scans/{id}/pr` | Open a GitHub PR with the fixes. |
| `GET`/`POST`/`DELETE` | `/integrations/github` | Connect / list / disconnect a repo. |

Interactive docs at `http://localhost:8000/docs`.

## 🧪 Tests & CI

```bash
make test     # pytest: scope guard, security, ownership, swarm, GitHub PR, usage, API auth + tenancy
```

GitHub Actions runs lint + the full suite against a Postgres service on every push.

## 📁 Project layout

```
redhive/
  agents/        orchestrator, recon, lead, probe (swarm), validator,
                 lead_review, reporter, patch, strategist, graph
  tools/         crawl, discover (path probing), security_headers, tls,
                 exposed_files, injection (xss/sqli), cors, csrf, open_redirect, outdated
  api/           FastAPI app + routers (auth, targets, scans, integrations)
  worker.py      background scan executor (SKIP LOCKED queue)
  github_pr.py   open remediation pull requests
  usage.py       per-scan token + cost tracking
  scope.py       the safety brake
demo_target/     bundled intentionally-vulnerable practice app
ui/              Next.js dashboard
migrations/      Alembic
tests/           pytest suite
```

## 🗺️ Roadmap

- Continuous / scheduled scans (cron re-scans with trend over time)
- Slack / Jira / Linear alerting; CI/CD webhook to scan on deploy
- Authenticated scanning (test behind login) + IDOR / SSRF coverage
- Runtime exploit validation; a fine-tuned offensive-security model

---

<div align="center">
<sub>Built as a working slice of the autonomous-pentest category. Authorized practice targets only.</sub>
</div>
