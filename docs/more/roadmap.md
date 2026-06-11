# MCTS Roadmap

> [Documentation](../index.md) → [More](README.md)

> **Using MCTS?** You only need [Getting started](../get-started/getting-started.md). This page is for project direction and contributors.

This document describes **where MCTS is today** (alpha), **what's shipped**, and **what's planned** in upcoming phases.

---

## Vision

MCTS aims to become the **default security tool for MCP servers** — the same way teams use `ruff check` for Python linting or Trivy for container scanning.

**North star:** Every MCP server repository runs `mcts scan` in CI before merge.

Today, MCTS identifies security issues across permissions, injection, tool abuse, data leakage, and attack chains. The next evolution adds deeper SAST, skills scanning, AI-BOM export, and runtime proxy capabilities.

**Operational docs (shipped features):** [Architecture](../analysis/architecture.md) · [CLI](../platform/cli.md) · [Scoring v2](../reporting/scoring-spec-v2.md) · [Migration](../migration/scoring-v2.md) · [CI](../platform/ci-integration.md)

Status labels used throughout this document:

| Label | Meaning |
|-------|---------|
| Shipped | Available in the current release |
| In progress | Actively being built |
| Planned | Scoped for an upcoming phase |
| Future | Longer-term vision |

---

## Current State (Alpha)

| Capability | Status |
|------------|--------|
| Permission analyzer | Shipped |
| Prompt injection simulator | Shipped (heuristic; live probing planned) |
| Tool abuse testing | Shipped |
| Data leakage detection | Shipped (source + metadata) |
| Multi-step attack chain detection | Shipped (capability-graph BFS) |
| Compliance checks (OWASP LLM Top 10) | Shipped |
| Exponential risk scoring (score + risk index) | Shipped |
| Multi-factor scoring v2 (`absolute_risk`, factor radar, corpus calibration) | Shipped (default `both`) |
| v2 CI gates + governance policy fields | Shipped |
| Terminal UI (Rich, themes, progress animation) | Shipped |
| JSON reports | Shipped |
| HTML security dashboard (`mcts report`) | Shipped |
| Category breakdown (HTML dashboard bars + radar) | Shipped |
| Live stdio probing (`--live`) | Shipped |
| Remote HTTP/SSE probing (`--url`) | Shipped |
| Protocol fuzzing (`mcts fuzz`) | Shipped |
| SARIF output (`--format sarif`) | Shipped |
| CI score thresholds (`--min-score`, `--max-critical`) | Shipped |
| Technique regression harness (79 techniques) | Shipped |
| Runtime telemetry analyzers (`--runtime-events`) | Shipped |
| CLI category breakdown + `--fail-on-category` | Shipped |
| GitHub Action (JSON + SARIF + HTML artifacts) | Shipped — `@v1` tag published |
| Agent pentest (`mcts pentest`) | Shipped (structured phases) |
| REST API (`mcts serve`) | Shipped |

### Known alpha gaps

See [Feature Expansion Plan — Part 1](feature-expansion-plan.md#part-1--current-state-honest-inventory) for the honest inventory.

- Multi-file repo discovery shipped; jailbreak analyzer uses weighted heuristic (not live payload injection)
- `mcts pentest` runs static recon, attack-chain review, and optional safe fuzz
- Semgrep SAST (`--semgrep`), LLM triage (`--llm-triage`), skills scan, vet, mcts-mcp, and machine-wide scan shipped
- Remote protocol fuzz (`mcts fuzz --url`) not yet supported — stdio only
- 79 / 79 bundled MCTS-T techniques in regression harness (≥80% accuracy gate)
- No CycloneDX AI-BOM export, runtime stdio proxy, or interactive attack-graph UI yet
- Trust registries and runtime gateways address adjacent layers MCTS does not replace

---

## Phase 0 — Foundation (Shipped)

> **Goal:** Fix structural limits so new features have a solid base.
> **Timeline:** ~2–3 weeks. See [Part 4 — Phase 0](feature-expansion-plan.md#phase-0--foundation-23-weeks).

| # | Deliverable | Status |
|---|-------------|--------|
| 0.1 | Multi-file **repository scanning** (`mcts scan ./repo/`) | Done |
| 0.2 | Parse **`input_schema`** + handler snippets | Done |
| 0.3 | **Source-aware analyzers** (secrets in code, command execution, path validation) | Done |
| 0.4 | Fix **placeholder analyzers** + **capability-graph** attack chains | Done — jailbreak uses weighted heuristic; live payload injection planned |

**New modules:** `discovery/static.py`, `core/target.py`, analyzers: `schema_surface`, `command_execution`, `path_validation`.

---

## Phase 1 — Adoption & Live Probing (Shipped)

> **Goal:** CI/CD adoption, live MCP enrichment, config inventory.
> **Timeline:** ~4–6 weeks. See [Part 4 — Phase 1](feature-expansion-plan.md#phase-1--adoption--live-probing-46-weeks).

| # | Deliverable | Status |
|---|-------------|--------|
| 1.1 | CI score thresholds (`--min-score`, `--max-critical`) | Done |
| 1.2 | GitHub Action (JSON + SARIF + HTML) | Done (`@v1` published) |
| 1.3 | SARIF output (`--format sarif`) | Done |
| 1.4 | Live MCP probing (`--live`, stdio) | Done |
| 1.5 | Config inventory (`mcts inventory`) | Done |
| 1.6 | Runtime telemetry analyzers (`--runtime-events`) | Done |
| 1.7 | Technique regression harness (79 techniques, ≥80% gate) | Done |
| 1.8 | CLI category breakdown + `--fail-on-category` gates | Done |

### 1. Security Risk Score (Category Breakdown in CLI) — Shipped

```
Overall Risk Score: 82/100 (Critical)

Breakdown:
  Excessive Permissions      30/30
  Prompt Injection Exposure  20/25
  Data Exfiltration Risk     15/20
  Tool Abuse Potential       12/15
  Secrets Handling            5/10
```

**Flags:** `--min-score 70`, `--max-critical 0`, `--fail-on-category permissions:10`

---

### 2. GitHub Action

Ship a published Action:

```yaml
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: 70
```

Upload JSON, SARIF, and HTML artifacts. Implementation: [`action/action.yml`](../../action/action.yml) — validated in CI via [`.github/workflows/action-validate.yml`](../../.github/workflows/action-validate.yml). Publish with `git tag v1`.

---

### 3. SARIF Output — Shipped

```bash
mcts scan ./server.py -o report.sarif --format sarif
```

Integrations: GitHub Advanced Security, GitLab, Azure DevOps, VS Code Security Panel.

---

### 4. Live MCP Probing — Shipped

```bash
mcts scan --live --command uv --args run,server.py
mcts scan --config ~/.cursor/mcp.json --server my-server
```

Stdio and remote HTTP/SSE; consent gate + `--i-understand-live-risk` for CI. Modules: `probe/session.py`, `probe/http_session.py`, `discovery/live.py`.

---

### 5. Config Inventory — Shipped

```bash
mcts inventory
mcts inventory --scan
```

Discover Cursor, Claude Desktop, VS Code configs. **Cross-server shadowing** analyzer (`MCTS-T-1008`).

---

### 6. Capability Profiles

Per-tool capability dimensions (reads untrusted input, egresses network, executes commands) feed attack chains. HTML **Capability Matrix** section still planned.

---

### 7. MCTS-T Technique Taxonomy — Shipped (core)

`technique_id` on findings; [taxonomy.md](../reporting/taxonomy.md); bundled Sigma rules. Technique Map in HTML dashboard still planned.

---

### 8. Benchmark Corpus

`examples/bench/` + regression fixtures + [scoring-spec.md](../reporting/scoring-spec.md) for gate semantics. Expanded corpus still planned.

---

## Phase 2 — Differentiation (In progress)

> **Goal:** Threat simulation and probing beyond static heuristics.
> See [Part 4 — Phase 2](feature-expansion-plan.md#phase-2--differentiation-610-weeks).

| # | Deliverable | Status | Command |
|---|-------------|--------|---------|
| 2.1 | Protocol fuzzing (safe defaults) | Shipped | `mcts fuzz` — see [fuzzing.md](../scanning/fuzzing.md) |
| 2.2 | Config audit (no LLM side effects) | Planned | `mcts audit-config` |
| 2.3 | Rug-pull baselines | Shipped | `--baseline` / `--save-baseline` |
| 2.4 | Description vs implementation drift | Partial | `BehavioralStaticAnalyzer` (SAST); full drift analyzer planned |
| 2.5 | TypeScript/JavaScript static discovery | Shipped | `discovery/static_js.py` — see [typescript-discovery.md](../scanning/typescript-discovery.md) |
| 2.6 | Scan history + trend chart | Shipped | `mcts_analysis/history.json` + HTML dashboard |
| 2.7 | Attack simulation mode | Planned | `mcts simulate` |
| 2.8 | Visual attack graph export | Planned | Mermaid, Graphviz, PNG |
| 2.9 | MCP marketplace scorecards | Planned | Public benchmark publishing |
| 2.10 | Remote protocol fuzz | Planned | `mcts fuzz --url` |
| 2.11 | Semgrep SAST adapter (+ Java) | Shipped | `--semgrep` optional extra |
| 2.12 | Skills / `SKILL.md` scanning | Shipped | W007–W014 via `skill_md` on `mcts scan` + `mcts inventory --skills` |
| 2.13 | Repo instruction discovery | Shipped | `SKILL.md`, `*prompt*.md`, `system_prompt.md` on static scans; `--instruction-file` / `--skills-dir` |
| 2.14 | Machine-wide config scan | Shipped | `mcts scan --machine-wide` |
| 2.15 | Interactive attack-graph dashboard | Partial | Static SVG in HTML; force-directed UI planned |
| 2.16 | Git-aware MCP config diff + PR comments | Planned | CI markdown output |
| 2.17 | Governance YAML policies | Shipped | `--policy` allowlist + min-score |
| 2.18 | CycloneDX / AI-BOM export | Planned | From inventory + scan metadata |

---

## Phase 3 — Platform & Community (Future)

> **Goal:** Recognized security standard in the MCP ecosystem.
> See [Part 4 — Phase 3](feature-expansion-plan.md#phase-3--platform-10-weeks).

| # | Deliverable |
|---|-------------|
| 3.1 | Package vetting (`mcts vet pypi:…` / `npm:…`) | Done |
| 3.2 | MCP server mode for IDE agents (`mcts-mcp`) | Done |
| 3.3 | Opt-in LLM review (`--llm-judge`, `--llm-triage`) | Done |
| 3.4 | Security baselines (`--profile strict\|balanced\|dev`) |
| 3.5 | Certification badges (`mcts badge`) |
| 3.6 | Expanded benchmark suite (Juice Shop–style MCP corpus) |
| 3.7 | Community hub — research, hall of fame, disclosures |
| 3.8 | Runtime stdio proxy (optional extra) — inline tool-call detectors |
| 3.9 | Continuous config watch daemon |
| 3.10 | Container / IaC scan (MCP-relevant subset) |
| 3.11 | Sigstore attestation + VEX triage |
| 3.12 | Optional trust-registry feed (read-only grades; no cloud scan required) |

---

## What We Will Not Build

Stay focused on MCP server-author security. Deferred or out of scope:

- Cloud-dependent analysis APIs (local-first default)
- Agent Guard / runtime monitoring hooks (integrate with gateways via SARIF/events)
- General-purpose 1,700-rule SAST
- Gamification or closed-source scanner cores
- Vendoring third-party threat framework corpora (link + map IDs only)
- Public trust registry as required OSS product (optional read-only feed only)
- Runtime MCP gateway / enterprise ACL plane (different product layer — integrate via SARIF/events)

Full rationale: [Feature Expansion Plan — Part 8](feature-expansion-plan.md#part-8--what-not-to-build).

---

## Priority Summary

| Phase | Focus | Key deliverables |
|-------|-------|------------------|
| **Phase 0–1** Yes | Foundation + adoption | Repo scan · SARIF · Action · live probe · inventory · taxonomy · fuzz |
| **Phase 2** | Differentiation + parity | Semgrep · skills · AI-BOM · attack-graph UI · audit-config · trends · remote fuzz |
| **Phase 3** | Platform | Vet · MCP tools · proxy · certification · optional registry feed |

### Suggested build order

```
Week 1-2:  Phase 0 (repo scan, source analyzers, attack graph)
Week 3-4:  SARIF, CI gates, publish Action
Week 5-6:  Live stdio probe
Week 7-8:  Inventory, capability profiles, cross-server
Week 9-10: MCTS-T taxonomy, benchmarks
Week 11+:  Phase 2
```

**First PR bundle:** repo discovery · source leakage/command analyzers · SARIF · `--min-score` · attack graph data fix.

---

## Success Criteria

Phase 1 is complete when:

- [x] CI gates on score/SARIF without cloud APIs
- [x] Scan works on a repo directory
- [x] Live stdio probe optional with consent
- [x] Findings include `technique_id`, `location`, `confidence`
- [x] Attack chains use capability graph
- [x] Benchmark/regression suite prevents detector regressions

Remaining Phase 1 polish: CLI/HTML Technique Map, capability matrix in dashboard.

Full checklist: [Feature Expansion Plan — Part 10](feature-expansion-plan.md#part-10--success-criteria).

---

## How to Contribute

1. Read [Feature Expansion Plan](feature-expansion-plan.md) for implementation detail.
2. Pick a phase item and open a [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml) or [Discussion](https://github.com/MCP-Audit/MCTS/discussions).
3. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for dev setup.

---

## Related

- [Feature Expansion Plan](feature-expansion-plan.md) — Full gap analysis and how-to
- [Architecture](../analysis/architecture.md) — Current and target pipeline
- [CLI Reference](../platform/cli.md) — Commands including planned surface
- [HTML Security Dashboard](../reporting/html-report.md)
