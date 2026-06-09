# Platform

> [Documentation](../index.md) → **Platform**

Operational guides for running MCTS locally, in CI, and via the published GitHub Action.

---

## Guides

| Page | Contents |
|------|----------|
| [CLI Reference](cli.md) | Complete reference: `scan`, `report`, `inventory`, `fuzz`, `readiness`, `serve`, all flags |
| [REST API](rest-api.md) | `mcts serve` — FastAPI (10 endpoints) |
| [CI Integration](ci-integration.md) | GitHub Action, SARIF upload, gate patterns, live/fuzz in CI, inventory audit |

---

## Commands at a glance

| Command | Purpose |
|---------|---------|
| `mcts scan` | Full security scan (static, live, remote, snapshot) |
| `mcts report` | JSON → HTML dashboard |
| `mcts inventory` | Local MCP config discovery |
| `mcts fuzz` | Protocol fuzz probes |
| `mcts readiness` | Production readiness (non-security) |
| `mcts serve` | REST API server |
| `mcts pentest` | Stub (planned) |
| `mcts vet` / `mcts-mcp` / `mcts watch` | Planned — see [CLI planned surface](cli.md#planned-commands-and-flags) |

---

## Planned platform capabilities

From the gap backlog — not yet shipped:

| Area | Planned | Doc |
|------|---------|-----|
| CLI subcommands | `inspect`, `vet`, `diff`, `watch`, `mcts-mcp`, `review` | [CLI planned](cli.md#planned-commands-and-flags) |
| CI | `--ci` preset, git-diff scan, PR comments, GitLab template | [CI Integration](ci-integration.md#planned-ci-capabilities) |
| Reporting | CycloneDX AI-BOM, Nucleus/OCSF export, trend charts | [Reporting planned](reporting/README.md#planned-reporting) |
| Discovery | 12+ clients, skills dirs, machine-wide scan | [Inventory planned](../scanning/inventory.md#planned-discovery) |

Full index: [Feature Expansion Plan Appendix](../more/feature-expansion-plan.md#part-11-appendix--full-gap-backlog-gap-001240).

## Related

- [Getting Started](../get-started/getting-started.md)
- [Scoring Specification](../reporting/scoring-spec.md)
- [GitHub Action README](../../action/README.md)
- [Documentation index](../index.md)
