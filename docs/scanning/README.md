# Scanning

> [Documentation](../index.md) → **Scanning**

Scanning is how MCTS **finds** MCP servers and **collects data** before analysis. You only need one scan mode for most workflows.

---

## Which scan mode should I use?

Answer these questions:

**Do you have the server's source code on disk?**
- **Yes** → `mcts scan ./server.py` or `mcts scan ./repo/` ([getting started](../get-started/getting-started.md))
- **Not sure which file** → `mcts scan . --auto`

**Confused by Overall Score vs Absolute Risk?** → [Scoring developer guide](../reporting/scoring-guide.md)

**Do you need what the server advertises at runtime?**
- Add `--live --i-understand-live-risk` → [Live scanning](live-scanning.md)

**Is the server hosted remotely (no local source)?**
- `--url https://...` → [Remote scanning](remote-scanning.md)

**Do you have an exported tools/list JSON and no network?**
- `--snapshot tools.json` → [Static snapshot](static-snapshot.md)

**Do you want to audit MCP configs on your machine?**
- `mcts inventory --scan` or `mcts scan --machine-wide` → [Config inventory](inventory.md)

**Do you want to stress-test protocol handling?**
- `mcts fuzz` then pipe events into scan → [Protocol fuzzing](fuzzing.md)

---

## Mode comparison

| Mode | Reads source | Starts server | Network | Command |
|------|:------------:|:-------------:|:-------:|---------|
| **Static** (default) | Yes | No | No | `mcts scan ./server.py` |
| **Live** | Optional | Yes | No | `mcts scan … --live --i-understand-live-risk` |
| **Remote** | No | No | Yes | `mcts scan . --url … --i-understand-live-risk` |
| **Snapshot** | No | No | No | `mcts scan . --snapshot tools.json` |
| **Inventory** | Config only | No | No | `mcts inventory --scan` |
| **Fuzz** | No | Yes | No | `mcts fuzz …` |

After discovery, all modes feed the same analyzers and produce the same report format (legacy `score` + v2 `score_v2` when `--scoring v2|both`, default `both`).

---

## Guides

| Guide | When to read it |
|-------|-----------------|
| [Live Scanning](live-scanning.md) | Probe a running local server |
| [Remote Scanning](remote-scanning.md) | Scan a hosted HTTP/SSE endpoint |
| [Static Snapshot](static-snapshot.md) | Air-gapped scan from JSON |
| [Protocol Fuzzing](fuzzing.md) | Protocol hardening tests |
| [TypeScript Discovery](typescript-discovery.md) | Node.js / TypeScript MCP servers |
| [Config Inventory](inventory.md) | Local MCP client configs + skills |
| [Readiness Scanning](readiness.md) | Production readiness (not security score) |

---

## Related

- [Getting started](../get-started/getting-started.md)
- [Security checks](../analysis/security-checks.md) — what runs after discovery
- [CLI reference](../platform/cli.md)
- [Documentation index](../index.md)
