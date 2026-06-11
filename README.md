# MCTS

**Model Context Threat Scanner**

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Security](https://img.shields.io/badge/focus-MCP%20Security-red)

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers — the programs that give AI assistants access to tools, files, databases, and APIs.

Run one command to find permission issues, injection risks, attack chains, and more. Works locally, in CI, with no cloud account required.

> **New to MCP or MCTS?** See the [documentation index](docs/index.md) and [glossary](docs/glossary.md).

```bash
mcts scan ./server.py   # single entrypoint
mcts scan ./            # entire repository
```

## Demo

Scan the included vulnerable MCP server:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

![MCTS scan demo](docs/assets/scan-demo.gif)

<details>
<summary>Example terminal output</summary>

```
$ mcts scan examples/vulnerable-mcp-server/server.py
==================== MCTS Security Report ====================
Overall Score:   1/100 (CRITICAL)        ← legacy (--min-score)
Risk Index:      100/100
Scoring basis:   5 Critical, 11 High, 1 Medium (17 scorable findings)
Absolute Risk:   2260 (critical)         ← v2 (--max-absolute-risk)
Security Score:  9/100                   ← v2 benchmark

Severity Summary          Top Findings
● Critical    5           [1] CRITICAL Destructive tool: delete_all_users
● High       11           [2] CRITICAL Read → exfiltration attack chain possible
● Medium      1           ...
```

Two scores on one scan is normal — see the [scoring developer guide](docs/reporting/scoring-guide.md).

</details>

## Problem

AI assistants connect to the outside world through **MCP servers** — small programs that expose callable tools (e.g. "delete user", "read file", "query database"). A misconfigured or malicious server can:

- Grant the AI destructive capabilities it shouldn't have
- Hide malicious instructions in tool descriptions
- Chain innocent tools into data theft or remote code execution
- Leak secrets embedded in server source code

Most teams ship MCP servers without dedicated security review. MCTS makes scanning as routine as running a linter.

## Features

MCTS is **alpha** software with a local-first MCP security pipeline — no cloud account required for standard scans. Full reference: [Security checks](docs/analysis/security-checks.md) · [CLI](docs/platform/cli.md).

### Scanning & discovery

| Capability | How |
|------------|-----|
| Repository & entrypoint scan | `mcts scan ./repo/` or `mcts scan ./server.py` — Python + TypeScript static discovery |
| Auto target resolution | `mcts scan . --auto` — pick entrypoint or lone MCP config server |
| Multi-surface analysis | `--surfaces tool,prompt,resource,instruction` |
| Repo instruction discovery | Default on static scans — `SKILL.md`, `*prompt*.md`, `system_prompt.md` → prompt/instruction analyzers |
| Live stdio probing | `--live --i-understand-live-risk` — merge runtime schemas with static context |
| Remote HTTP/SSE | `--url` + Bearer/OAuth — streamable HTTP and SSE transports |
| Air-gapped snapshot | `--snapshot tools.json` or `mcts snapshot` → offline scan |
| Machine-wide scan | `mcts scan --machine-wide` — all MCP servers in local client configs |
| Remote manifest probe | `mcts scan-mcp <url>` — pre-connect `tools/list` check |
| Per-technique mode | `--technique MCTS-T-*` — run one technique pack at a time |

### Security analysis

| Capability | How |
|------------|-----|
| Core metadata checks | Permissions, poisoning, FSP, shadowing, line-jumping, jailbreak resistance |
| Source-aware SAST | Secrets, command execution, path validation in handler code |
| Behavioral static SAST | Description vs implementation mismatch + taint (Python, TS, Go, Rust) |
| Semgrep SAST (opt-in) | `--semgrep` — bundled rules for Python, JS/TS, Java |
| Runtime telemetry | 50+ sub-detectors via `--runtime-events`, `--live`, or fuzz output |
| Attack chains | Capability-graph BFS (read → exfil, read → exec, …) |
| Cross-server analysis | Tool shadowing + toxic flows (`W015–W020`) with `--full-toxic-flows` |
| Sigma metadata rules | Bundled YAML + `--sigma-rules-path` |
| Rug-pull / baseline diff | `--baseline` / `--save-baseline` |
| Optional ML & intel | `--yara`, `--llm-judge`, `--llm-triage`, `--cloud-inspect`, `--virustotal` |
| MCTS-T taxonomy | Technique/mitigation IDs + crosswalk on every finding |
| Regression harness | **79/79** bundled techniques with ≥80% CI accuracy gate |

### Agent ecosystem & supply chain

| Capability | How |
|------------|-----|
| Client config inventory | `mcts inventory` — **12+** agent clients (Cursor, Claude, VS Code, Gemini, Codex, …) |
| Inventory batch scan | `mcts inventory --scan-all` |
| Skills scanning | `mcts scan ./skills` or `mcts inventory --skills` — `SKILL.md` checks (`W007–W014`) |
| Dependency CVE scan | `--pip-audit`, `--npm-audit` |
| Package pre-install vet | `mcts vet pypi:` / `npm:` / `oci:` |
| Structured pentest | `mcts pentest` — static recon, attack chains, optional safe fuzz |

### Reports, CI & governance

| Capability | How |
|------------|-----|
| Risk scoring | Legacy + v2 by default — [developer guide](docs/reporting/scoring-guide.md) |
| Compliance mapping | OWASP LLM Top 10 + OWASP MCP Top 10 (non-scoring meta-findings) |
| Terminal UI | Rich dashboard — themes, progress, `--terminal-format` views |
| Export formats | JSON, SARIF, HTML (`mcts report`) |
| CI gates | Legacy (`--min-score`) and/or v2 (`--max-absolute-risk`) — [guide](docs/reporting/scoring-guide.md#ci-gates--pick-one-strategy) |
| Governance policies | `--policy` YAML (legacy + optional v2 fields) |
| GitHub Action | JSON + SARIF + HTML artifacts ([`@v1`](action/README.md)) |
| Preflight | `mcts doctor` — deps, extras, and config hints |

### Platform & integrations

| Capability | How |
|------------|-----|
| REST API | `mcts serve` — 10 scan endpoints (`--extra api`) |
| MCP server mode | `mcts-mcp` — `scan_mcp_target`, `explain_finding`, `compare_baselines` for IDE agents |
| Readiness (non-security) | `mcts readiness` — HEUR-001–020 + optional OPA/LLM |
| Protocol fuzzing | `mcts fuzz` — safe read-only probes by default |
| Surface subcommands | `mcts scan-prompts`, `scan-resources`, `scan-instructions` (surface-scoped analyzers; no supply-chain noise) |
| Python API | `from mcts import Scanner, ScanConfig` |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended)

### Install

**Recommended — isolated tool install** (does not touch your app venv):

```bash
uvx mcp-mcts scan ./server.py
pipx install mcp-mcts
uv tool install mcp-mcts
```

> Distribution name is **`mcp-mcts`** (the generic `mcts` name is already taken on PyPI). The import package and CLI remain `mcts`.

**From PyPI in a dedicated environment** (not your application `.venv`):

```bash
pip install mcp-mcts
pip install "mcp-mcts[mcp]"        # live probing + fuzzing
pip install "mcp-mcts[api]"        # REST API (`mcts serve`)
pip install "mcp-mcts[llm]"        # LLM-as-judge / --llm-triage (install separately; not in [all])
pip install "mcp-mcts[semgrep]"    # Semgrep SAST adapter (--semgrep; also needs semgrep CLI)
```

Avoid `pip install mcp-mcts[all]` inside your app's dev venv — it can conflict with pinned dependencies.

| Install | Use case |
|---------|----------|
| `uvx mcp-mcts` | One-off scan, no install |
| `pipx install mcp-mcts` | Global isolated CLI |
| `pip install mcp-mcts[mcp]` | Live probing in a dedicated venv |
| `pip install mcp-mcts[all]` | All extras except LLM (no `litellm`) |
| `pip install 'mcp-mcts[all,llm]'` | Everything including `--llm-judge` / `--llm-triage` |

**From source** (contributors):

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

### Scan an MCP server

**Single entrypoint** — when you know the server file:

```bash
mcts scan ./server.py
mcts scan examples/vulnerable-mcp-server/server.py
```

**Entire repository** — when tools are spread across multiple files:

```bash
mcts scan .
mcts scan ./path/to/mcp-repo
mcts scan examples/bench/multi-file-server/
```

Repo mode walks Python and TypeScript sources, discovers MCP tools across the tree, and merges them into one report (skips `tests/`, venvs, and other excluded paths). For large monorepos, prefer scanning a single entrypoint (`mcts scan path/to/bridge.py`) or `mcts scan . --auto` before a full-repo scan.

Save JSON and generate an executive HTML dashboard:

```bash
mcts scan ./server.py -o report.json
mcts scan . -o report.json
mcts report report.json -o security-report.html
open security-report.html
```

The HTML report includes a dark-themed overview (score gauge, letter grade, severity cards, posture summary), risk breakdown with radar chart, searchable findings, attack chain graph, OWASP mapping, and in-browser export (JSON / HTML / PDF). See [docs/reporting/html-report.md](docs/reporting/html-report.md).

### CI gate (fail on critical or score)

```bash
# Legacy (unchanged)
mcts scan ./server.py --fail-on-critical --min-score 70

# v2 (default scoring includes score_v2)
mcts scan ./server.py --fail-on-critical --max-absolute-risk 500 --max-risk-level high

mcts scan . -o report.sarif --format sarif
```

Gate cheat sheet: [scoring guide](docs/reporting/scoring-guide.md#ci-gates--pick-one-strategy) · [CI integration](docs/platform/ci-integration.md) · [GitHub Action](action/README.md)

### Themes

```bash
uv run mcts scan ./server.py --theme cyber    # default
uv run mcts scan ./server.py --theme minimal --no-progress
```

## Architecture

```
  MCP server (file / repo / config)
              │
              ▼
     Discovery (static Py+TS, live stdio/HTTP, JSON snapshot)
              │
              ▼
     30+ security analyzers + compliance + MCTS-T taxonomy
     (core checks always on; 20+ per scan; opt-in via flags)
              │
              ▼
   Legacy score (overall) + v2 score (absolute_risk)
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
 Terminal   JSON/     HTML dashboard
 dashboard  SARIF    (mcts report)
```

## Documentation

**Start here:** [Install and first scan](docs/get-started/getting-started.md) (~15 min)

| I want to… | Guide |
|------------|-------|
| Understand scores | **[Scoring developer guide](docs/reporting/scoring-guide.md)** |
| Choose a scan mode | [Scanning overview](docs/scanning/README.md) |
| Set up CI | [CI integration](docs/platform/ci-integration.md) |
| Look up commands | [CLI reference](docs/platform/cli.md) |
| Understand findings | [Security checks](docs/analysis/security-checks.md) |

Full map (guides → reference → contributor docs): [docs/index.md](docs/index.md) · [Glossary](docs/glossary.md)

## Project Structure

```
MCTS/
├── src/mcts/          # Main package (src layout)
│   ├── cli/             # Typer CLI (`scan`, `report`, `inventory`, `fuzz`, `vet`, `pentest`, `mcts-mcp`, `serve`)
│   ├── core/            # Scanner orchestration, ScanConfig
│   ├── discovery/       # Static (Python/TS), live, JSON snapshot, merge
│   ├── probe/           # Stdio + HTTP sessions, auth, protocol checks
│   ├── analyzers/       # 25+ security analyzers (Semgrep, LLM triage, toxic flows, …)
│   ├── vet/             # Pre-install package vetting (pypi/npm/oci)
│   ├── pentest/         # Structured pentest runner
│   ├── mcp_server/      # `mcts-mcp` stdio tools for IDE agents
│   ├── governance/      # YAML policy + scan_gates (legacy + v2)
│   ├── readiness/       # Production readiness heuristics
│   ├── api/             # FastAPI REST server
│   ├── inventory/       # Client config + skills discovery
│   ├── fuzz/            # Protocol fuzz runner
│   ├── sast/            # Tree-sitter taint + Semgrep rule pack
│   ├── taxonomy/        # MCTS-T techniques, Sigma rules
│   ├── scoring/         # Risk scoring v1 + v2 engines, corpus stats, attack-graph paths
│   ├── compliance/      # OWASP & MCP compliance checks
│   ├── reporting/       # ScanReport models, SARIF, HTML entry
│   ├── report/          # HTML dashboard (templates, CSS, JS)
│   ├── ui/              # Terminal dashboard (Rich)
│   └── mcp/             # MCPServerInfo models
├── tests/               # pytest suite + regression fixtures
├── examples/            # Sample MCP servers & benchmarks
├── action/              # GitHub Action (`@v1`)
└── docs/                # Documentation
    ├── get-started/     # Install and first scan
    ├── scanning/        # Live, fuzz, TS discovery, inventory
    ├── analysis/        # Pipeline architecture
    ├── reporting/       # Scoring, taxonomy, HTML dashboard
    ├── platform/        # CLI and CI
    └── more/            # Roadmap and planning
```

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check src tests
uv run ruff format src tests
pre-commit install
```

## Positioning

MCTS is **MCP-boundary security** — tool metadata, schemas, handler source, client configs, protocol behavior, and capability-graph attack chains. It complements general AppSec tools; it does not replace Semgrep, Trivy, or enterprise runtime gateways.

| Tool category | Domain | MCTS overlap |
|---------------|--------|--------------|
| General SAST | Application code vulnerabilities | MCP tool poisoning, schema FSP, cross-server shadowing |
| HTTP DAST | Web application surface | MCP protocol + live tool manifest probes |
| Container / dependency scanners | Images and packages | `--pip-audit` / `--npm-audit` at the MCP repo layer |
| Agent fleet scanners | Agent + MCP inventory | Attack chains, MCTS-T taxonomy, readiness/OPA |
| Trust registries | Cloud scan + reputation | MCTS is local-first; no account required for CI |
| Runtime gateways | Runtime policy & governance | Different layer — MCTS scans before deploy; they enforce at runtime |

**Where MCTS leads today:** dual legacy + v2 multi-factor scoring (`absolute_risk`, factor radar, corpus-calibrated `security_score`), capability-graph attack chains, first-party MCTS-T taxonomy with bundled Sigma rules, executive HTML dashboard, readiness + OPA, YARA on metadata, line-jumping detection, Semgrep SAST adapter, LLM metadata triage, package vetting, MCP server mode (`mcts-mcp`), skills scanning, toxic-flow analysis, local-first default.

**Highest-priority gaps:** deep multi-language CFG/taint, prompt firewall, CycloneDX AI-BOM export, runtime stdio proxy, remote protocol fuzz (`mcts fuzz --url`), scan history/trends, hallucinated package detection, full Agno multi-agent pentest.

See [Product Positioning](docs/more/product-positioning.md) and [Feature Expansion Plan — Part 11](docs/more/feature-expansion-plan.md#part-11--prioritized-backlog).

## Roadmap

| Doc | Contents |
|-----|----------|
| [Feature Expansion Plan](docs/more/feature-expansion-plan.md) | Full gap analysis, how to implement each capability, module layout, build order |
| [Product Roadmap](docs/more/roadmap.md) | Phased deliverables: foundation → CI adoption → differentiation → platform |

**Next up (Phase 2–3):** CycloneDX AI-BOM export, scan history/trends, runtime stdio proxy, remote fuzz (`mcts fuzz --url`), prompt firewall, deep CFG/taint, `mcts audit-config`, interactive attack-graph UI. Phase 0–2 foundation is largely shipped — see [Roadmap](docs/more/roadmap.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
