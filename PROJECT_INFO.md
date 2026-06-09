# RedHive — Project Info

> AI-powered autonomous pentest agent. A demo product built to mirror **MindFort** (https://www.mindfort.ai/) for landing an interview / showing real skills.

---

## 1. Why this project exists

- **Goal:** Build a working slice of MindFort's product, then cold-pitch them (and similar security startups) for a software engineer / full-stack / AI role.
- **Strategy:** Don't do a take-home test — show a live demo that proves I can build their core loop.
- **Pitch line:**
  > "I read what MindFort is building and got obsessed — so I built a working slice: an autonomous LangGraph agent that maps a target's attack surface, reasons about what to probe, and produces triaged findings with proof + remediation. Runs in Docker, Postgres-backed, scanning OWASP Juice Shop. 2-min demo here. I'd love 15 min to show you."

---

## 2. What MindFort does (the target to mimic)

Autonomous AI security agents that continuously pentest apps & infrastructure.

- Point agent at a domain → maps attack surface, crawls, authenticates, tests within minutes
- Probes apps/APIs/infra 24/7 "like an attacker would"
- < 1% false positive rate
- Findings include **proof-of-exploit + reproduction steps**
- Generates **verified patches → pull requests**
- "HillClimb" self-learning system
- CI/CD triggers, Jira/Linear integration, live chat to steer investigation
- Customers: enterprises, startups, MSSPs (FinTech, healthcare, legal, telecom)
- Compliance: HIPAA, SOC 2, ISO 27001
- **Their stack:** Python, LangGraph/LangChain, Postgres, Docker, K8s

---

## 3. What RedHive will be (scoped MVP)

A web app: enter a target (from an allowlist) → AI agent runs a scan → produces a **triaged vulnerability report** with severity, evidence, repro steps, and an AI-suggested fix.

### Core loop (mirrors MindFort)
1. **Recon** — crawl target, enumerate pages/endpoints/forms, fingerprint tech
2. **Test** — run safe, well-known vulnerability checks
3. **Reason** — LLM agent decides what to probe next based on findings (the agentic differentiator)
4. **Report** — each finding: severity, proof, repro steps, remediation
5. **Patch (stretch)** — generate a fix diff / GitHub PR for code-level findings

---

## 4. ⚠️ Legal / ethical guardrail (NON-NEGOTIABLE)

- Only scan targets **I own or am explicitly authorized to test**.
- For the demo, scan **intentionally-vulnerable practice apps** deployed locally:
  - **OWASP Juice Shop** (Docker, one command)
  - **DVWA** (Damn Vulnerable Web App)
  - A small vulnerable Flask app I write
- Bake an **allowlist into the tool** that refuses any target not on it. This signals maturity to a security team.
- Never point it at real third-party sites.

---

## 5. Architecture

```
┌──────────────┐    ┌─────────────────────┐    ┌──────────────────┐
│  Next.js UI  │───▶│   FastAPI backend    │───▶│  LangGraph Agent │
│ - target box │    │ - /scans (start/get) │    │  (orchestrator)  │
│ - live log   │    │ - allowlist guard    │    └────────┬─────────┘
│ - report view│    │ - SSE/WebSocket logs │             │
└──────────────┘    └──────────┬───────────┘    ┌────────▼─────────┐
                               │                 │   Tools:          │
                        ┌──────▼──────┐          │ - crawler         │
                        │  Postgres   │          │ - header_check    │
                        │ scans,      │          │ - tls_check       │
                        │ findings    │          │ - tech_fingerprint│
                        └─────────────┘          │ - vuln_probe      │
                                                 │ - report_writer   │
                                                 └──────────────────┘
        Everything runs in Docker (mirror their stack)
```

---

## 6. The Agent (LangGraph — centerpiece)

LLM doesn't guess vulnerabilities — it **orchestrates tools** and reasons over real output.

| Tool | What it does | Library |
|---|---|---|
| `crawl(url)` | Discover pages, forms, endpoints, params | `httpx` + `BeautifulSoup` |
| `check_security_headers(url)` | Missing CSP, HSTS, X-Frame-Options, etc. | `httpx` |
| `check_tls(host)` | Weak TLS, expired cert | `ssl`, `sslyze` |
| `fingerprint(url)` | Detect server/framework/versions | headers + `wappalyzer` |
| `test_xss(form)` | Reflected XSS on a form (safe marker payload) | `httpx` |
| `test_sqli(param)` | Error-based SQLi indicators (safe probe) | `httpx` |
| `check_exposed_files(url)` | `/.git`, `/.env`, `/robots.txt`, backups | `httpx` |
| `write_finding(...)` | Structured finding → DB | — |

**Agentic flow example:** crawl → see login form → test XSS + SQLi → see server version header → check for known exposed files → write findings. The LLM picks *what to test next* (MindFort's value prop over static scanners).

---

## 7. Tech Stack (deliberately mirrors MindFort)

| Layer | Choice | Why |
|---|---|---|
| Agent | **LangGraph** (Python) | Their exact framework |
| Backend | **FastAPI** | Their stack |
| DB | **Postgres** | Their stack |
| Containers | **Docker** | Their stack |
| LLM | Claude / GPT-4o (tool calling) | Reasoning engine — DECIDE WHICH |
| Frontend | Next.js + Tailwind | Report UI + live log |
| Targets | Juice Shop / DVWA in Docker | Safe, legal |

---

## 8. Findings the agent can realistically detect (~2 weeks)

Reliable, safe, impressive without real exploit dev:
- Missing/weak **security headers** (CSP, HSTS, X-Content-Type-Options)
- **TLS** misconfig / weak ciphers / expired certs
- **Exposed sensitive files** (`.git`, `.env`, backups, directory listing)
- **Reflected XSS** (safe marker payload, confirm reflection)
- **Error-based SQLi** signals (DB error in response)
- **Outdated software** versions from fingerprinting → match small CVE list
- **Missing auth / IDOR** on guessable endpoints
- **Cookie flags** (missing HttpOnly/Secure/SameSite)

Each → finding with: severity, request/response evidence, repro steps, LLM-written remediation.

---

## 9. Build Plan (~2–3 weeks part-time)

- **Day 1–2:** Docker setup, deploy Juice Shop locally, FastAPI skeleton, Postgres schema (`scans`, `findings`), allowlist guard
- **Day 3–4:** Crawler tool + header/TLS/exposed-file checks. Store findings
- **Day 5–7:** LangGraph agent wiring tools + reasoning loop + structured findings
- **Day 8–9:** XSS/SQLi safe probes, severity scoring, LLM remediation writer
- **Day 10–11:** Next.js UI — target input, live scan log (SSE), report view
- **Day 12–13:** Stretch: auto-generate patch diff / GitHub PR for a code finding
- **Day 14:** Polish, deploy, record 2-min Loom, write pitch email

---

## 10. Cost (~$30–50/mo)

| Item | Cost |
|---|---|
| LLM API | $20–40/mo (cap per scan) |
| Hosting (Railway/Render + Vercel) | $0–10/mo |
| Targets (local Docker) | $0 |
| **Total** | **~$30–50/mo** |

---

## 11. Features that map to MindFort's pitch (mention in email)

- ✅ "Point at a domain, agent maps attack surface" → crawler + recon
- ✅ "Proof-of-exploit + repro steps" → structured findings
- ✅ "Low false positives" → agent verifies before reporting
- ✅ "Generates patches / PRs" → stretch feature (huge if shipped)
- ✅ "Continuous" → scheduled re-scan (cron) for bonus points
- ✅ Their exact stack (LangGraph/Python/Postgres/Docker)

---

## 12. Planned repo structure (NOT built yet)

```
RedHive/
├── docker-compose.yml        # Juice Shop (target) + Postgres + API
├── .env.example              # LLM API key slot
├── README.md
├── PROJECT_INFO.md           # this file
├── backend/                  # FastAPI app, Postgres schema, allowlist guard
└── agent/                    # LangGraph agent + tool stubs
```

---

## 13. Open decisions (TODO before building)

- [ ] LLM provider: Claude vs OpenAI
- [ ] Build order: backend + agent first, UI later (recommended)
- [ ] Check domain / GitHub availability for "RedHive"
- [ ] Confirm practice target: Juice Shop (recommended) vs DVWA

---

## 14. Other startups this demo also helps pitch

Same demo signals relevance to: **XBOW-style security startups, Pentera, Horizon3.ai**, and broadly any AI-agent/backend startup (Respan, Relixir, Hazel AI) since it shows LangGraph + agent + backend skills.

---

_Status: PLANNING ONLY. No code built yet. Next step = scaffold repo when ready._
