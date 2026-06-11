# Planned CLI commands and flags

> [Documentation](../index.md) → [More](README.md)

**Contributor / roadmap doc.** End users should use the [CLI reference](../platform/cli.md) for commands that exist today.

From the [Feature Expansion Plan — CLI appendix](feature-expansion-plan.md#scanning-29). Status reflects MCTS today vs the backlog.

---

## Planned subcommands

| Command | Status | Priority | Description |
|---------|--------|----------|-------------|
| `mcts audit-config` | Planned | P1 | Static review of `mcpServers` JSON |
| `mcts diff` | Planned | P1 | Git-aware MCP config diff; PR comment output |
| `mcts inspect` | Missing | P1 | Read-only tools/prompts/resources listing |
| `mcts vet` | Shipped | P0 | Pre-install `pypi:` / `npm:` / `oci:` vetting |
| `mcts review` / `cr-agent` | Missing | P1 | Dedicated LLM security review CLI |
| `mcts simulate` | Planned | P2 | Active attack-path simulation |
| `mcts pentest` | Shipped | P0 | Static recon + attack chains + optional safe fuzz |
| `mcts trend` | Planned | P2 | Score history from `.mcts/history/` |
| `mcts badge` | Planned | P3 | README certification SVG |
| `mcts watch` | Planned | P2 | Continuous config re-scan daemon |
| `mcts shadow` | Planned | P1 | Unknown/shadow MCP server discovery |
| `mcts dashboard` | Planned | P1 | Interactive attack-graph UI |
| `mcts-mcp` | Shipped | P0 | MCP server mode — `scan_mcp_target`, `explain_finding`, `compare_baselines` |
| `mcts guard install` | Missing | P0 | Agent Guard runtime hooks (defer/partner) |
| `mcts init` | Missing | P1 | Client setup wizard |
| `mcts doctor` | Shipped | P1 | Dependency and config preflight diagnostics |
| `mcts rules` | Missing | P3 | Expose Sigma/rule paths |
| `mcts scan-mcp` | Shipped | P2 | Pre-connect remote tools/list manifest probe |

---

## Planned global flags (selected)

| Flag / behavior | GAP | Priority |
|-----------------|-----|----------|
| `--technique MCTS-T-*` per-technique mode | GAP-001 | Shipped |
| `--semgrep` taint backend (+ Java) | GAP-002–003 | Shipped |
| Machine-wide scan (no explicit target) | GAP-006 | Shipped |
| `--skills` / SKILL.md scanning | GAP-029 | Shipped |
| `--full-toxic-flows` TF codes | GAP-032 | Shipped |
| `--ci` gate bundle | GAP-024 | Shipped |
| `--scoring v2\|both` + v2 gates | — | Shipped (default `both`) |
| `--policy` governance YAML | GAP-222 | Shipped |
| `--scan-all-users` multi-home | GAP-021 | P1 |
| `--diff-base` git-scoped scan | GAP-010 | P1 |
| GitHub URL scan target | GAP-009 | P2 |
| `--stdio-timeout`, `--skip-ssl-verify` | GAP-017, GAP-023 | P2 |
| `--ignore-issues-codes` CI allowlist | GAP-025 | P2 |
| `mcts fuzz --url` remote protocol fuzz | GAP-190 | P2 |

---

## Full CLI/scanning gap list (selected)

| GAP | Planned surface | Status | Notes |
|:----|:----------------|:-------|:------|
| GAP-001 | Per-technique scan mode | Shipped | `--technique MCTS-T-*` |
| GAP-002 | Semgrep taint backend | Shipped | `--semgrep` |
| GAP-003 | Java SAST | Shipped | Part of Semgrep adapter |
| GAP-068 | LLM metadata triage | Shipped | `--llm-triage` |
| GAP-004 | Agentic pentest | Shipped | `mcts pentest` |
| GAP-005 | Pre-install package vet | Shipped | `mcts vet` |
| GAP-006 | Machine-wide default scan | Shipped | `--machine-wide` |
| GAP-008 | known-configs scan all | Shipped | `inventory --scan-all` |
| GAP-029 | Skills / SKILL.md scan | Shipped | `inventory --skills` |
| GAP-007 | Batch config scan | Missing | All servers in one MCP JSON |
| GAP-009 | GitHub URL scan target | Missing | Shallow clone / zip |
| GAP-010 | Git-diff scoped scan | Missing | `--diff-base` for PR CI |

See [Roadmap](roadmap.md) and [Feature Expansion Plan Part 11](feature-expansion-plan.md#part-11--prioritized-backlog).
