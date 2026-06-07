# Getting Started

**MCTS** (Model Context Threat Scanner) — security analysis for MCP servers.

## Install

From source (development):

```bash
git clone https://github.com/MCP-Audit/MCTS.git
cd MCTS
uv sync --all-extras
```

Live probing and fuzzing require the `mcp` extra: `uv sync --extra mcp`.

## Scan your first server

### Single Python file

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py
```

### Repository (Python + TypeScript)

```bash
uv run mcts scan examples/bench/multi-file-server/
```

MCTS walks the repo, discovers MCP tools from Python `@tool` decorators and TypeScript `registerTool` / `server.tool` patterns, and runs security analyzers against schemas and handler source.

## Example output

```text
[✓] Discovering tools...
[✓] Mapping permissions...
[✓] Detecting attack chains...
[✓] Generating report...

==================== MCTS Security Report ====================
Overall Score:   5/100 (CRITICAL)
Risk Index:      100/100
Scoring basis:   3 Critical, 7 High, 2 Medium, 0 Low (12 scorable findings)

● Critical    4
● High        7
● Medium      2
● Low         0
```

Scores are computed from findings (not hardcoded). The terminal dashboard includes a **category risk breakdown**. See [Scoring Specification](scoring-spec.md) and [CLI Reference](cli.md).

## Save JSON and SARIF

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.sarif --format sarif
```

## HTML security dashboard

Share results with stakeholders using the interactive HTML report:

```bash
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
open security-report.html
```

The dashboard includes score gauge, grade, severity cards, category breakdown + radar chart, searchable findings, OWASP mapping, and attack chain graph. See [HTML Security Dashboard](html-report.md).

## Live probing (optional)

Connect to a running stdio MCP server to enrich tool schemas:

```bash
uv run mcts scan examples/live-mcp-server/server.py \
  --live --i-understand-live-risk
```

See [Live Scanning](live-scanning.md) for config-based launch and CI consent (`MCTS_LIVE_OK=1`).

## Discover local MCP configs

```bash
uv run mcts inventory
uv run mcts inventory --scan -o inventory.json
```

See [Config Inventory](inventory.md).

## Protocol fuzzing

```bash
uv run mcts fuzz examples/live-mcp-server/server.py \
  --fuzz-level safe --i-understand-live-risk

# Pipe fuzz telemetry into a full scan
uv run mcts scan examples/live-mcp-server/server.py \
  --runtime-events fuzz.json
```

See [Protocol Fuzzing](fuzzing.md).

## CI gate

```bash
uv run mcts scan ./server.py --fail-on-critical --min-score 70
```

GitHub Action: [CI Integration](ci-integration.md) · [action/README.md](../action/README.md)

## Next steps

- Try example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/`
- TypeScript repos: [TypeScript Discovery](typescript-discovery.md)
- Technique IDs on findings: [Threat Taxonomy](taxonomy.md)
- Full pipeline: [Architecture](architecture.md)
- Roadmap: [Feature Expansion Plan](feature-expansion-plan.md) · [Product Roadmap](roadmap.md)
