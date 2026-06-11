# MCTS Documentation

**MCTS** scans [MCP](https://modelcontextprotocol.io) servers for security issues — permissions, injection, secrets, attack chains, supply chain risk, and cross-server toxic flows — locally or in CI.

**Ships today:** repo/live/remote/snapshot scanning · 30+ analyzers · 79-technique regression suite · attack chains · inventory across 12+ agent clients · skills scan · vet/pentest · SARIF/HTML reports · GitHub Action · optional Semgrep, LLM triage, and `mcts-mcp` server mode.

---

## Start here (15 minutes)

**New to MCTS?** Read one guide, run one command, done.

1. **[Install and first scan](get-started/getting-started.md)** — install, scan the example server, read the output, export HTML
2. **Two scores on the same scan?** **[Scoring developer guide](reporting/scoring-guide.md)** — 5 min, answers 90% of score questions
3. Stuck on a term? **[Glossary](glossary.md)**

You do **not** need to read the CLI reference, architecture doc, or planning docs to get value from MCTS.

### Typical developer path

```
Install → first scan → scoring guide (if confused) → CI integration → done
```

Contributors add: [Architecture](analysis/architecture.md) → [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## I want to…

Pick the task that matches what you are doing right now:

| Task | Start here |
|------|------------|
| Scan my MCP server code | [Getting started → Scan your first server](get-started/getting-started.md#scan-your-first-server) — `mcts scan ./server.py` |
| Scan a whole repo | `mcts scan ./repo/` — same guide, [repo section](get-started/getting-started.md#scan-a-whole-repository) |
| Not sure which file to scan | `mcts scan . --auto` — [auto scan](get-started/getting-started.md#optional-one-command-auto-scan) |
| Probe a **running** server | [Live scanning](scanning/live-scanning.md) — needs `--live --i-understand-live-risk` |
| Scan a **hosted** URL | [Remote scanning](scanning/remote-scanning.md) — `--url` + auth |
| Scan with **no network** (exported JSON) | [Static snapshot](scanning/static-snapshot.md) — `--snapshot` |
| **Choose a scan mode** (decision tree) | [Which scan mode should I use?](scanning/README.md#which-scan-mode-should-i-use) |
| Understand scan scores | **[Scoring developer guide](reporting/scoring-guide.md)** — start here |
| Fail CI on bad scores | [CI integration](platform/ci-integration.md) — see scoring guide for gate cheat sheet |
| Share results with leadership | [HTML report](reporting/html-report.md) — `mcts report report.json -o report.html` |
| See what's installed on my machine | [Config inventory](scanning/inventory.md) — `mcts inventory --scan` |
| Scan all local MCP configs | `mcts scan --machine-wide` — [CLI reference](platform/cli.md) |
| Understand a finding | [Security checks](analysis/security-checks.md) |
| Look up a flag or command | [CLI reference](platform/cli.md) |

---

## Common commands

```bash
# Install once (isolated — not in your app venv)
pipx install mcp-mcts
# or one-off: uvx mcp-mcts scan ./server.py

# Basic scan
mcts scan ./server.py

# Save JSON + HTML dashboard
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html

# CI gate
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.sarif --format sarif
```

More commands: [CLI reference](platform/cli.md)

---

## Documentation map

Three tiers — read top to bottom only as needed.

### Tier 1 — Guides (most users stop here)

| Topic | Guide |
|-------|-------|
| Install + first scan | [Getting started](get-started/getting-started.md) |
| Which scan mode to use | [Scanning overview](scanning/README.md) |
| Live / remote / snapshot / fuzz / inventory | [Scanning guides](scanning/README.md#guides) |
| CI and GitHub Action | [CI integration](platform/ci-integration.md) |
| Understand scores | **[Scoring developer guide](reporting/scoring-guide.md)** |
| HTML and SARIF reports | [Reporting overview](reporting/README.md) |

### Tier 2 — Reference (when you need details)

| Topic | Guide |
|-------|-------|
| Every command and flag | [CLI reference](platform/cli.md) |
| Every security check | [Security checks](analysis/security-checks.md) |
| Scoring (legacy + v2) | **[Scoring developer guide](reporting/scoring-guide.md)** → [legacy spec](reporting/scoring-spec.md) · [v2 spec](reporting/scoring-spec-v2.md) |
| Technique IDs (MCTS-T-*) | [Threat taxonomy](reporting/taxonomy.md) |
| REST API | [REST API](platform/rest-api.md) |
| Term definitions | [Glossary](glossary.md) |

### Tier 3 — Contributors & planning (skip unless building MCTS)

| Topic | Guide |
|-------|-------|
| Roadmap and shipped vs planned | [Product roadmap](more/roadmap.md) |
| Gap analysis and implementation plan | [Feature expansion plan](more/feature-expansion-plan.md) |
| Product positioning | [Product positioning](more/product-positioning.md) |
| Contributing code | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| CLI roadmap / GAP tables | [Planned CLI](more/planned-cli.md) |

---

## By role

| Role | Path |
|------|------|
| Developer (first time) | [Getting started](get-started/getting-started.md) → [Scanning overview](scanning/README.md) |
| MCP server author | [Getting started](get-started/getting-started.md) → [Security checks](analysis/security-checks.md) |
| DevOps / CI | [Scoring developer guide](reporting/scoring-guide.md) → [CI integration](platform/ci-integration.md) |
| Security engineer | [Architecture](analysis/architecture.md) → [Security checks](analysis/security-checks.md) |
| Agent / platform team | [Inventory](scanning/inventory.md) → [CLI reference](platform/cli.md) |
| Contributor | [CONTRIBUTING.md](../CONTRIBUTING.md) → [Quick start](../CONTRIBUTING.md#quick-start-for-first-time-contributors) | [Architecture](analysis/architecture.md) |

---

## Other links

- [Changelog](../CHANGELOG.md)
- [Report a vulnerability](../SECURITY.md)
- [Main README](../README.md)
