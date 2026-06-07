# MCTS

**Model Context Threat Scanner**

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Security](https://img.shields.io/badge/focus-MCP%20Security-red)

Security analysis purpose-built for Model Context Protocol (MCP) servers — permissions, injection, attack chains, and risk scoring.

Make MCP threat scanning as easy as running a linter.

```bash
mcts scan ./server.py
```

## Demo

Scan the included vulnerable MCP server:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

```
$ mcts scan examples/vulnerable-mcp-server/server.py
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCTS Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium (12 scorable findings)
Formula:         3×25 + 7×10 + 2×3 = 151 → round(100 × e^(-151/50)) = 5

Severity Summary          Top Findings
● Critical    4           [1] CRITICAL Destructive tool: delete_all_users
● High        7           [2] CRITICAL Read → exfiltration attack chain possible
● Medium      2           ...
```

> **Tip:** Record a terminal GIF of the scan above and add it here as `docs/assets/scan-demo.gif` for maximum README impact.

## Problem

MCP servers expose databases, APIs, file systems, cloud resources, and SaaS tools to AI agents — often without rigorous security review. MCTS helps teams find issues before attackers do.

## Features

| Module | Status | Description |
|--------|--------|-------------|
| Permission Analyzer | ✅ Alpha | Flags destructive and over-privileged tools |
| Prompt Injection Simulator | ✅ Alpha | Tests known injection attack patterns |
| Tool Abuse Testing | ✅ Alpha | Detects path traversal and misuse surfaces |
| Data Leakage Detection | ✅ Alpha | Scans for secrets and sensitive references |
| Agent Jailbreak Testing | 🚧 Planned | Resistance scoring against jailbreak suites |
| Multi-Step Attack Chains | ✅ Alpha | Identifies dangerous tool combinations |
| Risk Scoring Engine | ✅ Alpha | Security score + risk index (exponential decay) |
| Terminal UI | ✅ Alpha | Rich dashboard, themes (`cyber`, `minimal`, `github`) |
| Compliance Checks | ✅ Alpha | OWASP LLM Top 10 & MCP best practices |
| CI/CD Integration | 🚧 Planned | GitHub Action for pipeline gates |
| HTML Security Dashboard | ✅ Alpha | Enterprise HTML report — gauge, grades, OWASP, attack chains |
| MCP Fuzzer | ✅ Alpha | `mcts fuzz` — safe read-only protocol probes by default |
| MCTS Agent | 🔮 Roadmap | `mcts pentest` |

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended)

### Install

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

### Scan an MCP server

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

Save JSON and generate an executive HTML dashboard:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
open security-report.html
```

The HTML report includes a dark-themed overview (score gauge, letter grade, severity cards, posture summary), risk breakdown with radar chart, searchable findings, attack chain graph, OWASP mapping, and in-browser export (JSON / HTML / PDF). See [docs/html-report.md](docs/html-report.md).

### CI gate (fail on critical)

```bash
uv run mcts scan ./server.py --fail-on-critical
```

### Themes

```bash
uv run mcts scan ./server.py --theme cyber    # default
uv run mcts scan ./server.py --theme minimal --no-progress
```

## Architecture

```
           ┌──────────────┐
           │ MCP Server   │
           └──────┬───────┘
                  │
                  ▼
         ┌─────────────────┐
         │ MCTS Scanner  │
         └─────────────────┘
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
Permission   Injection     Leakage
Analyzer      Engine       Scanner
     ▼            ▼            ▼
       Risk Scoring Engine
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
  Terminal UI          HTML Dashboard
  (Rich CLI)      (mcts report)
```

## Documentation

- [Getting Started](docs/getting-started.md)
- [CLI Reference](docs/cli.md)
- [HTML Security Dashboard](docs/html-report.md)
- [Architecture](docs/architecture.md)
- [Feature Expansion Plan](docs/feature-expansion-plan.md) — detailed implementation guide
- [Product Roadmap](docs/roadmap.md) — phased deliverables
- [Building in public (blog)](docs/blog-building-mcp-security-in-public.md) — alpha status, gaps, community discussion
- [Changelog](CHANGELOG.md)

## Project Structure

```
MCTS/
├── src/mcts/          # Main package (src layout)
│   ├── cli/             # Typer CLI (`scan`, `report`, `fuzz`, `pentest`)
│   ├── core/            # Scanner orchestration
│   ├── analyzers/       # Security analyzers
│   ├── scoring/         # Risk scoring engine
│   ├── compliance/      # OWASP & MCP compliance checks
│   ├── reporting/       # ScanReport models & JSON
│   ├── report/          # HTML dashboard (templates, CSS, JS)
│   ├── brand/           # Logo assets
│   ├── ui/              # Terminal dashboard (Rich)
│   └── mcp/             # MCP client & discovery
├── tests/               # pytest suite
├── examples/            # Sample vulnerable MCP servers
├── action/              # GitHub Action (planned)
└── docs/                # Documentation
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

| Tool | Domain |
|------|--------|
| SonarQube | Code quality |
| OWASP ZAP | Web security |
| Trivy | Container security |
| Semgrep | Static analysis |
| **MCTS** | **MCP security** |

## Roadmap

| Doc | Contents |
|-----|----------|
| [Feature Expansion Plan](docs/feature-expansion-plan.md) | Full gap analysis, how to implement each capability, module layout, build order |
| [Product Roadmap](docs/roadmap.md) | Phased deliverables: foundation → CI adoption → differentiation → platform |

**Next up (Phase 0–1):** repo-wide scanning, source-aware analyzers, SARIF, published GitHub Action, live MCP probing, config inventory, MCTS-T technique taxonomy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Security

To report vulnerabilities, see [SECURITY.md](SECURITY.md).
