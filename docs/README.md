# MCTS Docs

> Start here: **[Documentation index](index.md)**

MCTS (Model Context Threat Scanner) documentation — installation through CI integration, scoring, taxonomy, and roadmap.

---

## Sections

| Section | Purpose | Start here |
|---------|---------|------------|
| [Get Started](get-started/README.md) | Install and first scan | [getting-started.md](get-started/getting-started.md) |
| [Scanning](scanning/README.md) | Live, fuzz, TS, inventory | [scanning/README.md](scanning/README.md) |
| [Analysis](analysis/README.md) | Pipeline and analyzers | [architecture.md](analysis/architecture.md) |
| [Reporting](reporting/README.md) | Score, taxonomy, HTML | [scoring-spec.md](reporting/scoring-spec.md) |
| [Platform](platform/README.md) | CLI and CI | [cli.md](platform/cli.md) |
| [More](more/README.md) | Roadmap, positioning, gap backlog, expansion plan | [roadmap.md](more/roadmap.md) |

---

## Quick commands

```bash
uv sync --all-extras
uv run mcts scan examples/vulnerable-mcp-server/server.py
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
```

---

## Changelog

- [Changelog](../CHANGELOG.md)
