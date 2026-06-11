# Platform

> [Documentation](../index.md) → **Platform**

How to **run MCTS** from the CLI, in CI, or via HTTP API.

> **New user?** Complete [Getting started](../get-started/getting-started.md) first — you do not need every flag on day one.

---

## Most-used commands

| Command | Purpose |
|---------|---------|
| `mcts scan` | Security scan (default workflow) |
| `mcts report` | JSON → HTML dashboard |
| `mcts inventory` | List / scan local MCP configs |
| `mcts doctor` | Preflight before first scan |

Everything else (`vet`, `pentest`, `fuzz`, `mcts-mcp`, `serve`) is optional — see [CLI reference](cli.md).

---

## Guides

| Page | Read when… |
|------|------------|
| [CLI Reference](cli.md) | You need a specific flag or subcommand |
| [CI Integration](ci-integration.md) | You are wiring MCTS into a pipeline |
| [REST API](rest-api.md) | You need HTTP endpoints instead of the CLI |

---

## Typical workflows

```bash
# Daily development
mcts scan ./server.py

# CI gate (legacy)
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.sarif --format sarif

# CI gate (v2 — scoring is both by default)
mcts scan ./server.py --max-absolute-risk 500 --max-risk-level high -o report.sarif --format sarif

# Share with stakeholders
mcts scan ./server.py -o report.json && mcts report report.json -o report.html
```

---

## Contributor docs

CLI roadmap and GAP tracking: [Planned CLI](../more/planned-cli.md) (not needed for normal use).

---

## Related

- [Getting started](../get-started/getting-started.md)
- [Documentation index](../index.md)
