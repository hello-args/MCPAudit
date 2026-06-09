# Product Positioning

> [Documentation](../index.md) → [More](README.md)

What **MCTS** (Model Context Threat Scanner) is built for, who it serves, what it delivers today, and where the roadmap is headed.

---

## What MCTS is

MCTS is a **local-first MCP server security scanner** for server authors, platform security teams, and agent infrastructure engineers. It discovers tools from Python and TypeScript source (or optional live stdio/HTTP/SSE probes), runs 20 analyzers by default (25+ with optional flags), scores risk with auditable math, and outputs terminal dashboards, JSON, SARIF, and executive HTML reports — **without requiring a cloud API** for standard scans.

```bash
mcts scan ./repo/ -o report.json --min-score 70
mcts report report.json -o security-report.html
mcts inventory --scan -o inventory.json
```

MCTS sits at the **MCP boundary**: tool metadata, JSON schemas, handler source, client configs, and protocol behavior — not generic application pentesting.

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
| **CI adoption** | SARIF 2.1.0, `--min-score`, `--max-critical`, `--fail-on-category`, published GitHub Action `@v1` |
| **Risk intelligence** | Exponential security score, risk index, auditable `ScoreBasis`, seven category dimensions |
| **Threat model** | Capability-graph attack chains (read→exfil, read→exec), not keyword-only heuristics |
| **Reporting** | Rich terminal UI (3 themes), executive HTML dashboard, OWASP LLM mapping, attack graph |
| **Taxonomy** | First-party `MCTS-T-*` techniques and `MCTS-M-*` mitigations on every finding |
| **Discovery** | Repo-wide Python + TypeScript static scan; optional stdio or remote HTTP/SSE live probe with merge |
| **Inventory** | Cursor, Claude, VS Code, Windsurf configs + MCTS-T-1008 shadow detection |
| **Probing** | Consent-tiered protocol fuzz (`safe` read-only default); runtime telemetry analyzers |
| **Offline default** | No LLM or vendor API required for standard `mcts scan` |
| **Regression safety** | 34+ technique fixtures; CI harness ≥80% accuracy gate |

---

## Primary use cases

### 1. Pre-merge security gate

Fail PRs when critical findings exist or score drops below team threshold:

```bash
mcts scan ./server.py --fail-on-critical --min-score 70 --max-critical 0
```

Integrate via [CI Integration](../platform/ci-integration.md) or GitHub Action.

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
| Compliance mapping | Yes | OWASP LLM Top 10 meta-findings (non-scoring) |
| Sigma metadata rules | Yes | Bundled + `--sigma-rules-path` |
| Semantic secrets | Yes | Opt-in `--semantic-secrets` |
| Baseline / rug-pull | Yes | `--baseline` / `--save-baseline` |
| Regression harness | Yes | 34+ fixtures, ≥80% CI gate |
| HTML dashboard | Yes | `mcts report` |
| GitHub Action | Yes | JSON + SARIF + HTML artifacts |

---

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
| Auditable exponential score + category gates | Shipped |
| MCTS-T taxonomy + bundled SAF Sigma metadata rules | Shipped |
| Executive HTML dashboard (local, no server) | Shipped |
| Readiness heuristics + OPA policies | Shipped |
| YARA on tool metadata | Shipped (opt-in) |
| Line-jumping analyzer | Shipped |
| Local-first / offline default | Shipped |

---

## Complete gap index

Summary of **213 actionable backlog items** (GAP-001–240, excluding 27 already-shipped parity items):

| Category | Gaps | P0 highlights |
|----------|-----:|---------------|
| Scanning | 29 | Per-technique SAF mode, Semgrep/Java, vet, machine-wide scan, pentest |
| Analyzer | 47 | Behavioral SAST depth, prompt firewall, hallucinated packages, skill scanning |
| CLI | 20 | inspect, guard, evo fleet, skills, init/doctor, cr-agent |
| Discovery | 13 | 12+ clients, VS Code profiles, Claude Code globs, skills dirs |
| Enterprise | 13 | MCP server mode, fleet upload, SOC2 eval, quarantine |
| Integration | 11 | Claude plugin, Smithery, MCP tool explain_finding |
| Reporting | 10 | Auto-fix, history/trend, dual taxonomy, redaction |
| Supply Chain | 9 | CycloneDX, OSV, SBOM diff/hallucination, typosquat engine |
| Taxonomy | 8 | Full 73 SAF rules, mitigations, regression scale |
| Auth | 5 | Full OAuth client flow, MCP SDK provider |
| CI / Script / Packaging | 17 | PyPI publish, 3-OS matrix, live CI, pre-commit |
| SDK / REST / Utility / Fuzz / Data / Docs | 35 | Public SDK, WebSocket fuzz, file_magic, eval corpus |
| Ecosystem-only (GAP-218–240) | 23 | Attack graph UI, proxy, Nucleus, Sigstore, watch daemon |

**Ecosystem matrix (Part B):** 74 layer features (L1–L10) where MCTS is missing or planned — SQL depth, ANSI smuggling, ASI misconfigs, runtime identity, MITRE ATLAS, credential flow graph, reputation network, etc. See [Appendix B](feature-expansion-plan.md#part-11-appendix-b--ecosystem-layer-gaps-l1l10).

---

## Known gaps (roadmap summary)

| Gap | Status | Target phase |
|-----|--------|--------------|
| Semgrep taint + Java SAST | Missing | Phase 2 |
| Skills / `SKILL.md` scanning | Missing | Phase 2 |
| Machine-wide config scan (no explicit target) | Missing | Phase 2 |
| MCP server mode for IDE agents | Missing | Phase 3 |
| CycloneDX / AI-BOM export | Missing | Phase 2–3 |
| Interactive attack-graph dashboard | Partial | Phase 2 |
| Runtime stdio proxy (inline detectors) | Missing | Phase 3 |
| Governance YAML + allowlist policies | Partial | Phase 2 |
| Remote protocol fuzz (`mcts fuzz --url`) | Planned | Phase 2 |
| Deep multi-language SAST (tree-sitter / taint) | Partial | Phase 2 |
| Package vetting (`mcts vet`) | Planned | Phase 3 |
| Agent-assisted pentest (`mcts pentest`) | Stub | Phase 3 |
| Scan history / trend charts | Planned | Phase 2 |
| SBOM / VEX / Sigstore attestation | Partial | Phase 2–3 |
| Container / IaC scan | Missing | Phase 3 |
| Multi-LLM consensus panel (opt-in) | Partial | Phase 3 |
| Public trust registry | Not planned (core) | Future optional |
| Full OAuth client flow | Weak | Phase 3 |
| 12+ agent client discovery | Partial | Phase 2 |
| Prompt firewall + action gate | Missing | Phase 2 |
| Hallucinated package detection | Missing | Phase 2 |
| Toxic flow / skill issue codes (E/W/TF) | Partial | Phase 2 |
| AIVSS / CVSS scoring modes | Missing | Phase 4 |
| Claude Code plugin / VS Code extension | Missing | Phase 4 |
| ANSI/control-char smuggling checks | Partial | Phase 2 |
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
