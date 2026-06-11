# Product Positioning

> [Documentation](../index.md) → [More](README.md)

> **Using MCTS to scan?** Start with [Getting started](../get-started/getting-started.md). This page is for stakeholders evaluating MCTS.

This document explains **what MCTS is built for**, **who uses it**, **what it does well today**, and **what's planned next**.

---

## What MCTS is

MCTS is a **local-first security scanner for MCP servers**. It helps teams find vulnerabilities in the tools, prompts, and resources that AI assistants can access — before deployment.

**In one sentence:** MCTS is to MCP servers what Semgrep is to application code, or Trivy is to containers.

Key properties:
- **Runs locally** — no cloud account required for standard scans
- **Works in CI** — SARIF output, score gates, published GitHub Action
- **MCP-specific** — checks tool permissions, description poisoning, attack chains, and protocol behavior that general SAST tools miss
- **Transparent scoring** — legacy 0–100 index plus v2 multi-factor `absolute_risk`, factor breakdown, and corpus-calibrated benchmark score

```bash
mcts scan ./repo/
mcts report mcts_analysis/scan-report.json   # optional — HTML is written on scan
mcts inventory --scan -o inventory.json
```

**Output paths:** Relative `-o` paths (e.g. `-o report.json`) are saved under **`mcts_analysis/`** in the current project directory — not the cwd root. After scan, open `mcts_analysis/scan-report.html` directly, or run `mcts report report.json` (auto-resolves to `mcts_analysis/report.json`).

MCTS focuses on the **MCP boundary** — tool metadata, JSON schemas, handler source code, client configs, and protocol behavior. It does not replace general application pentesting or runtime policy enforcement.

---

## Who MCTS is for

| Persona | Primary workflow |
|---------|------------------|
| **MCP server author** | Pre-release scan of tool definitions and handler code |
| **Platform / AppSec** | CI gate on MCP repos; SARIF in GitHub Advanced Security |
| **Agent infra team** | Inventory local MCP configs; detect cross-server shadowing |
| **Security leadership** | HTML dashboard for posture reviews and remediation tracking |
| **Research / red team** | Fuzz + runtime telemetry for protocol and metadata attacks |

---

## Core strengths

| Area | What MCTS provides |
|------|-------------------|
| **CI adoption** | SARIF 2.1.0 (incl. `mcts/scoreV2`), legacy + v2 gates, published GitHub Action `@v1` |
| **Risk intelligence** | Dual legacy + v2 scoring, factor-axis radar, `top_contributors`, attack-chain multiplier, auditable `ScoreBasis` |
| **Threat model** | Capability-graph attack chains (read→exfil, read→exec), not keyword-only heuristics |
| **Reporting** | Rich terminal UI (3 themes), executive HTML dashboard, OWASP LLM + MCP mapping, MCTS-T technique grid, capability matrix, attack graph, scan history trend |
| **Taxonomy** | First-party `MCTS-T-*` techniques and `MCTS-M-*` mitigations on every finding |
| **Discovery** | Repo-wide Python + TypeScript static scan; optional stdio or remote HTTP/SSE live probe with merge |
| **Inventory** | Cursor, Claude, VS Code, Windsurf configs + MCTS-T-1008 shadow detection |
| **Probing** | Consent-tiered protocol fuzz (`safe` read-only default); runtime telemetry analyzers |
| **Offline default** | No LLM or vendor API required for standard `mcts scan` |
| **Regression safety** | 79 technique fixtures; CI harness ≥80% accuracy gate |

---

## Primary use cases

### 1. Pre-merge security gate

Fail PRs when critical findings exist or score drops below team threshold:

```bash
# Legacy gates
mcts scan ./server.py --fail-on-critical --min-score 70 --max-critical 0

# v2 gates (scoring both is default)
mcts scan ./server.py --max-absolute-risk 500 --max-risk-level high
```

Integrate via [CI Integration](../platform/ci-integration.md) or GitHub Action. See [Scoring v2 migration](../migration/scoring-v2.md).

### 2. MCP server author review

Static analysis of tool metadata, JSON schemas, and handler source before publishing to a registry or sharing with agents. Catches description poisoning, missing path validation, command execution, and excessive permissions.

### 3. Executive reporting

Share HTML dashboards with security and leadership — score gauge, grade, category radar, prioritized recommendations, OWASP mapping. No separate reporting server required.

### 4. Config hygiene

Inventory installed MCP servers and detect tool name collisions across clients:

```bash
mcts inventory --scan
```

Maps to cross-server agent confusion risk (MCTS-T-1008).

### 5. Regression safety for detectors

Technique fixtures under `tests/fixtures/regression/` ensure analyzer changes do not silently reduce coverage.

---

## Capability coverage matrix

| Layer | Shipped | Notes |
|-------|---------|-------|
| Static metadata analysis | Yes | Poisoning, FSP, permissions, shadowing, line jumping |
| Source-aware SAST | Yes | Secrets, command execution, path validation in handlers |
| Live stdio probe | Yes | `--live`; merges protocol schemas with static context |
| Remote HTTP/SSE probe | Yes | `--url` + `--transport`; Bearer/OAuth — see [Remote Scanning](../scanning/remote-scanning.md) |
| REST API | Yes | `mcts serve` — 10 endpoints (`--extra api`) |
| Protocol fuzz | Yes | `mcts fuzz`; pipe `runtime_events` into scan |
| Runtime telemetry | Yes | OAuth, rug-pull, injection via `--runtime-events` |
| Attack chains | Yes | Capability-graph BFS on tool profiles |
| Compliance mapping | Yes | OWASP LLM + MCP Top 10 meta-findings with coverage gaps (non-scoring) |
| Sigma metadata rules | Yes | Bundled + `--sigma-rules-path` |
| Semantic secrets | Yes | Opt-in `--semantic-secrets` |
| Baseline / rug-pull | Yes | `--baseline` / `--save-baseline` |
| Regression harness | Yes | 79 technique fixtures, ≥80% CI gate |
| HTML dashboard | Yes | Auto-written to `mcts_analysis/scan-report.html`; `mcts report` optional |
| GitHub Action | Yes | JSON + SARIF + HTML artifacts |
| Semgrep SAST + Java | Yes | `--semgrep` optional adapter |
| LLM metadata triage | Yes | `--llm-triage` malicious/safe/suspect |
| Package vetting | Yes | `mcts vet pypi:` / `npm:` / `oci:` |
| MCP server mode | Yes | `mcts-mcp` stdio tools |
| Skills scanning | Yes | `mcts inventory --skills` W007–W014 |
| Machine-wide scan | Yes | `mcts scan --machine-wide` |
| Structured pentest | Yes | `mcts pentest` |
| Governance policies | Yes | `--policy` YAML allowlist |
| Toxic flows | Yes | W015–W020 with `--full-toxic-flows` |

## Comparison framing

MCTS is complementary to general-purpose AppSec tooling:

| Tool category | Focus | MCTS focus |
|---------------|-------|------------|
| SAST | General code vulnerabilities | MCP tool boundary, schemas, agent abuse |
| DAST | HTTP application surface | MCP protocol + tool metadata |
| Container scanners | Images and OS packages | MCP server behavior and configs |
| Agent fleet scanners | Fleet inventory, skills, toxic flows | Attack chains, MCTS-T taxonomy, readiness |
| Config-only MCP scanners | Client JSON misconfigs, cross-server flows | Repo SAST + live probe + scoring in one CLI |
| Supply-chain / AI-BOM platforms | AI-BOM, blast radius, runtime proxy | Pre-deploy scan; local-first CI gate |
| Trust registries | Public grades, badges, cloud consensus | Offline scan; no account for standard CI |
| Runtime gateways | Live tool-call policy, ACLs, audit logs | Scan-time posture; not a runtime enforcer |
| **MCTS** | — | **MCP-specific threat model, attack chains, auditable scoring** |

Run MCTS **in addition to** existing AppSec tooling on MCP server repositories.

---

## Differentiation

| Capability | Status |
|------------|--------|
| Capability-graph attack chains (BFS) | Shipped |
| Dual legacy + v2 scoring (`absolute_risk`, factor radar, corpus calibration) | Shipped |
| Auditable exponential score + legacy/v2 CI gates | Shipped |
| MCTS-T taxonomy + bundled Sigma metadata rules | Shipped |
| Executive HTML dashboard (local, no server) | Shipped |
| MCTS-T full technique grid + capability matrix in HTML | Shipped |
| Scan history trend chart in HTML | Shipped (`mcts_analysis/history.json`) |
| Readiness heuristics + OPA policies | Shipped |
| YARA on tool metadata | Shipped (opt-in) |
| Line-jumping analyzer | Shipped |
| Local-first / offline default | Shipped |

---

## Complete gap index

Summary of **213 actionable backlog items** (GAP-001–240, excluding 27 already-shipped parity items):

| Category | Gaps | P0 highlights |
|----------|-----:|---------------|
| Scanning | 29 | Deep CFG/taint, prompt firewall, CycloneDX, remote fuzz |
| Analyzer | 47 | Behavioral SAST depth, prompt firewall, hallucinated packages, skill scanning |
| CLI | 20 | inspect, guard, evo fleet, skills, init/doctor, cr-agent |
| Discovery | 13 | 12+ clients, VS Code profiles, Claude Code globs, skills dirs |
| Enterprise | 13 | MCP server mode, fleet upload, SOC2 eval, quarantine |
| Integration | 11 | Claude plugin, Smithery, MCP tool explain_finding |
| Reporting | 10 | Auto-fix, dual taxonomy redaction; history/trend **shipped** |
| Supply Chain | 9 | CycloneDX, OSV, SBOM diff/hallucination, typosquat engine |
| Taxonomy | 8 | Full Sigma rule corpus, mitigations, regression scale |
| Auth | 5 | Full OAuth client flow, MCP SDK provider |
| CI / Script / Packaging | 17 | PyPI publish, 3-OS matrix, live CI, pre-commit |
| SDK / REST / Utility / Fuzz / Data / Docs | 35 | Public SDK, WebSocket fuzz, file_magic, eval corpus |
| Ecosystem-only (GAP-218–240) | 23 | Attack graph UI, proxy, Nucleus, Sigstore, watch daemon |

**Ecosystem matrix (Part B):** 74 layer features (L1–L10) where MCTS is missing or planned — SQL depth, ANSI smuggling, ASI misconfigs, runtime identity, MITRE ATLAS, credential flow graph, reputation network, etc. See [Appendix B](feature-expansion-plan.md#part-11-appendix-b--ecosystem-layer-gaps-l1l10).

---

## Known gaps (roadmap summary)

| Gap | Status | Target phase |
|-----|--------|--------------|
| Semgrep taint + Java SAST | Shipped | Phase 2 |
| Skills / `SKILL.md` scanning | Shipped | Phase 2 |
| Machine-wide config scan (no explicit target) | Shipped | Phase 2 |
| MCP server mode for IDE agents | Shipped | Phase 3 |
| Package vetting (`mcts vet`) | Shipped | Phase 3 |
| LLM metadata triage (`--llm-triage`) | Shipped | Phase 2 |
| Structured pentest (`mcts pentest`) | Shipped | Phase 3 |
| Governance YAML + allowlist policies | Shipped | Phase 2 |
| Toxic flow / skill issue codes (E/W/TF) | Shipped | Phase 2 |
| ANSI/control-char smuggling checks | Shipped | Phase 2 |
| 12+ agent client discovery | Shipped | Phase 2 |
| CycloneDX / AI-BOM export | Missing | Phase 2–3 |
| Interactive attack-graph dashboard | Planned | Phase 2 — static SVG shipped; force-directed UI pending |
| Runtime stdio proxy (inline detectors) | Missing | Phase 3 |
| Remote protocol fuzz (`mcts fuzz --url`) | Planned | Phase 2 |
| Deep multi-language SAST (tree-sitter / taint) | Partial | Phase 2 |
| Scan history / trend charts | Shipped | Phase 2 — `mcts_analysis/history.json` + HTML sparkline |
| SBOM / VEX / Sigstore attestation | Partial | Phase 2–3 |
| Container / IaC scan | Missing | Phase 3 |
| Multi-LLM consensus panel (opt-in) | Partial | Phase 3 |
| Prompt firewall + action gate | Missing | Phase 2 |
| Hallucinated package detection | Missing | Phase 2 |
| AIVSS / CVSS scoring modes | Missing | Phase 4 |
| Claude Code plugin / VS Code extension | Missing | Phase 4 |
| Managed agent ASI misconfigs | Missing | Phase 2 |
| MITRE ATLAS + multi-framework compliance | Missing | Phase 4 |
| Programmatic Scanner SDK | Missing | Phase 3 |
| Pre-commit hook installer | Missing | Phase 4 |
| WebSocket transport fuzz | Missing | Phase 3 |
| Global reputation / benchmarking network | Missing | Future |

Details: [Product Roadmap](roadmap.md) · [Feature Expansion Plan — full appendix](feature-expansion-plan.md#part-11-appendix--full-gap-backlog-gap-001240)

---

## Design principles

1. **Deterministic by default** — scores and gates must work without LLM calls
2. **MCP-boundary focus** — tool metadata, schemas, handlers, configs, protocol behavior
3. **Consent before execution** — live probe and aggressive fuzz require explicit flags
4. **Auditable output** — every score traceable via `ScoreBasis`; findings carry `technique_id`
5. **Lean core install** — live/fuzz behind optional `mcp` extra
6. **First-party taxonomy** — `MCTS-T-*` on reports; external frameworks inform patterns only

---

## Related

- [Architecture](../analysis/architecture.md)
- [Threat Taxonomy](../reporting/taxonomy.md)
- [External Frameworks](external-frameworks.md)
- [Roadmap](roadmap.md)
- [CLI Reference](../platform/cli.md)
