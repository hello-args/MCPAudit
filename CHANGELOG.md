# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **HTML security dashboard** — `mcts report` renders a self-contained, dark-themed executive dashboard (score gauge, letter grade, severity cards, posture summary, category breakdown + radar chart, findings table, attack chain graph, OWASP mapping, in-browser JSON/HTML/PDF export)
- **Terminal UI** — Rich-based CLI with themes (`cyber`, `minimal`, `github`), scan progress animation, aligned metrics panels, and brand PNG logo on supported terminals (ASCII fallback elsewhere)
- **Exponential risk scoring** — Security score `round(100 × e^(-raw_risk/50))`, risk index, and auditable `ScoreBasis` on every report (compliance meta-findings excluded)
- Example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/` for scoring regression bands
- Brand assets in `src/mcts/brand/` (canonical logo + HTML-optimized embed)
- Docs: [HTML Security Dashboard](docs/html-report.md), updated CLI, getting started, architecture, and README

### Changed

- Renamed project and repository to **MCTS** (Model Context Threat Scanner): `mcts` package and CLI, GitHub repo `MCTS/MCTS` (formerly MCPAudit / `mcpaudit` / `MCP-Audit/MCPAudit`)
- `mcts report` now delegates to the premium dashboard generator (replaces minimal inline HTML template)

## [0.1.0] - 2026-06-03

### Added

- Initial project scaffold with `uv`, `src/` layout, and `pyproject.toml`
- CLI: `mcts scan`, `mcts report`, `mcts fuzz`, `mcts pentest` (stubs)
- Analyzers: permissions, prompt injection, tool abuse, data leakage, jailbreak, attack chains
- Risk scoring engine and basic HTML report generation
- Example vulnerable MCP server and pytest suite
- GitHub Actions CI, pre-commit, and OSS community files
- Alpha release: static analysis scanner for Python MCP servers
