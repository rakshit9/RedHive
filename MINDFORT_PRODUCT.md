# MindFort — What They Build (Reference)

> Source: https://www.mindfort.ai/ (fetched). This is the product RedHive mimics.

---

## The one-liner
**An autonomous AI pentesting platform.** They deploy swarms of AI agents that continuously hack your own apps (with permission) to find security holes *before* real attackers do — then they even write the fix.

Think: "a team of AI hackers on staff, working 24/7, that you point at your website."

---

## The problem they solve
- Companies need constant security testing, but:
  - Human pentesters are **expensive, slow, and only test once or twice a year**.
  - Traditional automated scanners (DAST) are **dumb** — tons of false alarms, miss real issues.
- MindFort's answer: **AI agents that think like a hacker, run continuously, and rarely cry wolf.**

---

## The product — step by step

**1. Point it at a target**
- Give it a domain. Agents **automatically map the attack surface** — crawl the site, find pages/APIs, even **log in (authenticate)** to test behind login walls.
- Setup in **minutes**, first results in **hours**.

**2. Continuous autonomous testing**
- Agents **"probe your apps, APIs, and infrastructure around the clock like an attacker would."**
- Runs on a schedule — daily, weekly, or custom. Not a one-time scan.
- They deploy **"thousands of agents that simulate teams of hackers"** — the multi-agent part.

**3. Finds real vulnerabilities, not noise**
- **Less than 1% false positive rate** (headline claim).
- Every finding comes with **proof-of-exploit + reproduction steps**.

**4. Fixes them automatically** ← big differentiator
- Generates **verified patches** for the vulnerabilities.
- Opens **pull requests** so the team just reviews and merges. Competitors only *find*; MindFort also *fixes*.

**5. Learns and improves — "HillClimb"**
- Self-learning system: agents **get better at finding vulnerabilities over time**, claiming to outperform traditional scanners.

---

## Workflow integration
- **CI/CD triggers** — scans automatically on code push/deploy.
- **Jira / Linear integration** — findings become tickets.
- **Live chat interface** — talk to the agents mid-investigation and steer them.

---

## Who buys it
- Enterprises, startups, and **MSSPs** (managed security service providers).
- Verticals: FinTech, banks, healthcare, legal tech, manufacturing, telecom.
- Compliance-driven orgs: **SOC 2, HIPAA, ISO 27001**.

---

## Tech stack (from their job post)
- **Python**, **LangChain / LangGraph** (multi-agent orchestration), **Postgres**, **Docker**, **Kubernetes**, LLMs.

---

## Notable metrics they advertise
- Setup time: **minutes**
- First results: **hours**
- Coverage: **24/7**
- False positives: **< 1%**

---

## The 3 things that make them special (RedHive must show these)
1. **Agentic, not a scanner** — agents *reason* about what to test next, like real hackers.
2. **Proof + low false positives** — verify findings before reporting.
3. **Auto-remediation (patches + PRs)** — close the loop, not just open tickets.

---

## MindFort feature → RedHive demo mapping

| MindFort feature | RedHive demo |
|---|---|
| Swarm of agents | Small team: Recon → Test → Validator → Reporter (3–5 agents) |
| Maps attack surface | crawler + endpoint discovery |
| Real exploits | Safe, well-known checks only (headers, XSS, SQLi signals, exposed files) on PRACTICE targets |
| Authenticates & tests behind login | Stretch goal |
| < 1% false positives | Validator agent re-confirms each finding |
| Proof + repro steps | structured findings |
| Auto-patch + PR | Stretch — biggest "wow" if shipped |
| Continuous / CI/CD | Add a scheduled re-scan |
| HillClimb learning | Simplified: remember what worked across runs |

---

## Goal reminder
RedHive does NOT need to be as good as MindFort. It needs a **working slice that proves I understand and can build their core loop** — enough to land the interview.
