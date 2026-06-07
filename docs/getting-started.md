# Getting Started

**MCTS** (Model Context Threat Scanner) — security analysis for MCP servers.

## Install

```bash
pip install mcts
# or with uv
uv tool install mcts
```

## Scan your first server

```bash
mcts scan ./server.py
```

MCTS performs static analysis on Python MCP servers, discovering `@tool` decorators and running security analyzers against them.

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

Scores are computed from findings (not hardcoded). See [CLI Reference](cli.md) for `--theme` and `--no-progress`.

## HTML security dashboard

Share results with stakeholders using the interactive HTML report:

```bash
mcts scan examples/vulnerable-mcp-server/server.py -o report.json
mcts report report.json -o security-report.html
```

Open `security-report.html` in Chrome, Firefox, Safari, or Edge. The dashboard includes:

- Executive overview with score gauge, grade, and severity cards
- Security posture summary and prioritized recommendations
- Risk breakdown (category bars + radar chart)
- Searchable findings, OWASP mapping, and attack chain graph

See [HTML Security Dashboard](html-report.md) for layout and export options. Release notes: [CHANGELOG](../CHANGELOG.md).

## Next steps

- Save JSON: `mcts scan ./server.py -o report.json`
- Generate HTML: `mcts report report.json -o security-report.html`
- Try example servers: `examples/safe-mcp-server/`, `examples/medium-risk-mcp-server/`
- Add to CI: see `action/action.yml` and [Roadmap — GitHub Action](roadmap.md#2-github-action)
- Read the plan: [Feature Expansion Plan](feature-expansion-plan.md) · [Product Roadmap](roadmap.md)
