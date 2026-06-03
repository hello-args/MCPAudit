# MCPAudit Roadmap

MCPAudit aims to become the **default security platform for the MCP ecosystem** — the CVSS-style scorecard, CI gate, and threat intelligence layer for AI agent tooling.

This document captures planned work, phased by impact and adoption potential. Status labels:

| Label | Meaning |
|-------|---------|
| ✅ Shipped | Available in the current release |
| 🚧 In progress | Actively being built |
| 📋 Planned | Scoped for an upcoming phase |
| 🔮 Future | Longer-term vision |

---

## Vision

Today, MCPAudit identifies security issues across permissions, prompt injection, tool abuse, data leakage, and attack chains. The next evolution turns those findings into **actionable risk intelligence** that teams can compare, track over time, and enforce in CI/CD — the same way teams use Trivy for containers or Semgrep for code.

**North star:** Make `mcpaudit scan` as standard in MCP projects as `ruff check` is in Python projects.

---

## Current State (Alpha)

| Capability | Status |
|------------|--------|
| Permission analyzer | ✅ Shipped |
| Prompt injection simulator | ✅ Shipped |
| Tool abuse testing | ✅ Shipped |
| Data leakage detection | ✅ Shipped |
| Multi-step attack chain detection | ✅ Shipped |
| Compliance checks (OWASP LLM Top 10) | ✅ Shipped |
| Overall risk score (0–100) | ✅ Shipped (basic) |
| JSON + HTML reports | ✅ Shipped |
| GitHub Action scaffold | 🚧 In progress |
| Agent jailbreak testing | 📋 Planned |
| Dynamic attack simulation | 📋 Planned |

The scoring engine today applies severity-weighted penalties to produce a single overall score. The roadmap below expands this into category breakdowns, threat mapping, and CI-native outputs.

---

## Phase 1 — Highest Impact (2026 Q3)

> **Goal:** Adoption in CI/CD pipelines and security workflows.  
> **Success metrics:** GitHub Action usage, SARIF integrations, score-based gating.

### 1. Security Risk Score (Category Breakdown)

Extend the scoring engine from a single number to a **security scorecard** with per-category breakdowns.

**Example output:**

```
Overall Risk Score: 82/100 (Critical)

Breakdown:
  Excessive Permissions      30/30
  Prompt Injection Exposure  20/25
  Data Exfiltration Risk     15/20
  Tool Abuse Potential       12/15
  Secrets Handling            5/10
```

**Why it matters:**

- Compare MCP servers side-by-side
- Track improvements across releases
- Set CI thresholds (`--min-score 70`)

**Positioning:** CVSS for MCP · Security scorecard for AI agents

---

### 2. GitHub Action

Ship a first-class GitHub Action so teams can add MCP security scanning in one step:

```yaml
- uses: hello-args/MCPAudit@v1
  with:
    target: ./server.py
    fail-on-critical: true
```

**Expected CI output:**

```
Security Report Generated

Critical: 2
High:     4
Medium:   6

Build Failed
```

A stub exists in [`action/action.yml`](../action/action.yml). Phase 1 completes packaging, publishing, and documentation.

---

### 3. SARIF Output

Add SARIF as a first-class report format alongside JSON, HTML, and Markdown:

```bash
mcpaudit scan ./server.py -o report.sarif --format sarif
```

**Integrations unlocked:**

- GitHub Advanced Security / code scanning
- GitLab Security Dashboard
- Azure DevOps
- VS Code Security Panel

Many enterprise security teams require SARIF before adopting a tool in CI.

---

## Phase 2 — Differentiation (2026 Q4)

> **Goal:** Move beyond static analysis toward offensive security tooling.  
> **Success metrics:** Research citations, demo engagement, unique attack coverage.

### 4. MITRE ATT&CK-Style MCP Threat Mapping

Publish a threat matrix mapping MCP-specific attacks to detection status:

| Attack | Detected |
|--------|----------|
| Prompt Injection | ✅ |
| Tool Escalation | ✅ |
| Credential Theft | ❌ |
| Data Exfiltration | ✅ |
| Arbitrary File Access | ⚠️ |

This would be among the first MCP-native threat frameworks — valuable for security researchers and compliance teams.

---

### 5. Attack Simulation Mode

Move from static checks to **active simulation**:

```bash
mcpaudit simulate server.py
```

Simulated attack paths:

- Prompt injection chains
- Data extraction via tool chaining
- Privilege escalation across tools

**Example output:**

```
Attack #3 succeeded

User Prompt
  ↓
Tool A (search)
  ↓
Tool B (browser)
  ↓
Tool C (filesystem)
  ↓
Sensitive Data Exposed
```

Differentiates MCPAudit from linters and static analyzers.

---

### 6. Visual Attack Graphs

Render discovered attack paths as interactive graphs:

```
User → Prompt → Search Tool → Browser Tool → Filesystem Tool → Sensitive Data
```

**Export formats:** Mermaid · Graphviz · HTML · PNG

Security researchers and incident responders expect visual attack chains.

---

### 7. MCP Server Marketplace Scanner

Scan popular MCP servers and publish public scorecards:

**Top Secure MCP Servers**

| Rank | Server | Score |
|------|--------|-------|
| 1 | Filesystem MCP | 92 |
| 2 | GitHub MCP | 88 |

**Most Risky MCP Servers**

| Rank | Server | Score |
|------|--------|-------|
| 1 | XYZ MCP | 22 |
| 2 | ABC MCP | 18 |

**Benefits:** Visibility · Research content · Community backlinks · Ecosystem trust signals

---

## Phase 3 — Platform & Community (2027)

> **Goal:** Become a recognized security standard in the MCP ecosystem.  
> **Success metrics:** Certification badges in the wild, benchmark adoption, contributor growth.

### 8. LLM-Based Security Analysis

Hybrid analysis combining static rules with LLM reasoning:

| Layer | Role |
|-------|------|
| Static analysis | Pattern matching, known bad signatures |
| Rule engine | Policy enforcement, compliance mapping |
| LLM reasoning | Nuanced interpretation of tool descriptions and prompts |

**Example:**

```
Tool Description: "Can execute shell commands on user request."

Risk:     Critical
Reason:   Tool permits arbitrary command execution without an
          authorization boundary.
```

---

### 9. MCP Server Certification

Generate verifiable certification badges for READMEs and marketplaces:

![MCPAudit Certified](https://img.shields.io/badge/MCPAudit-Certified-gold)

**Levels:** Bronze · Silver · Gold · Platinum

Open-source MCP projects will display these badges — driving organic adoption.

---

### 10. Security Baselines

Environment-aware policy profiles:

```bash
mcpaudit check server.py --baseline strict
```

| Profile | Use case |
|---------|----------|
| Enterprise | Strictest controls, full compliance |
| Startup | Balanced security vs. velocity |
| Research | Relaxed for experimentation |
| Personal | Minimal local-dev checks |

Different environments need different policies.

---

### 11. Benchmark Dataset

Expand [`examples/`](../examples/) with intentionally vulnerable MCP servers:

```
examples/
  vulnerable-mcp-server/     # existing
  vulnerable_filesystem/
  vulnerable_shell/
  vulnerable_github/
  vulnerable_browser/
```

**Inspired by:** OWASP Juice Shop · DVWA · Damn Vulnerable MCP Server

Used for testing, demos, contributor onboarding, and regression benchmarks.

---

### 12. Community & Research

Grow beyond a CLI tool into a community hub:

- **Roadmap** — This document, updated each quarter
- **Hall of Fame** — Contributors, researchers, responsible disclosures
- **Research section** — MCP security papers, known vulnerabilities, threat reports
- **Discussions** — Q&A, ideas, and show-and-tell ([GitHub Discussions](https://github.com/hello-args/MCPAudit/discussions))

---

## Priority Summary

If the goal is **stars, contributors, and visibility**, build in this order:

| Phase | Focus | Key deliverables |
|-------|-------|------------------|
| **Phase 1** | Adoption | Category risk score · GitHub Action · SARIF |
| **Phase 2** | Differentiation | Attack simulation · Attack graphs · Marketplace scanner |
| **Phase 3** | Platform | Certification badges · Baselines · Benchmark suite · Research hub |

---

## How to Contribute

Pick a Phase 1 item and open a [feature request](https://github.com/hello-args/MCPAudit/issues/new?template=feature_request.yml) or start a [Discussion](https://github.com/hello-args/MCPAudit/discussions) to align on design before opening a PR.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.

---

## Related

- [Architecture](architecture.md)
- [CLI Reference](cli.md)
- [Feature matrix (README)](../README.md#features)
