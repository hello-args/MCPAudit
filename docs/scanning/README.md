# Scanning

> [Documentation](../index.md) → **Scanning**

MCTS discovers MCP servers through **static source analysis**, optional **live stdio probing**, **protocol fuzzing**, and **client config inventory**. Discovery output becomes `MCPServerInfo` — the input to all security analyzers.

---

## Mode selection guide

| Your situation | Recommended mode | Command |
|----------------|------------------|---------|
| Python/TS source in repo | Static scan | `mcts scan ./repo/` |
| Need runtime tool schemas | Static + live merge | `mcts scan ./repo/ --live --i-understand-live-risk` |
| Hosted HTTP MCP server | Remote probe | `mcts scan . --url https://... --i-understand-live-risk` |
| Air-gapped CI | Static JSON snapshot | `mcts scan . --snapshot tools.json` |
| npm package, no source | Config + live | `mcts scan . --config ... --server X --live ...` |
| Prompt/resource poisoning | Multi-surface scan | `mcts scan ... --surfaces tool,prompt,resource,instruction` |
| Protocol hardening test | Fuzz → scan pipeline | `mcts fuzz ... -o fuzz.json` then `--runtime-events` |
| Audit laptop MCP installs | Inventory | `mcts inventory --scan` |
| Production readiness | Readiness (non-security) | `mcts readiness ./repo/` |
| Node server, no `npm install` | TS static discovery | `mcts scan ./repo/ --languages typescript` |

---

## Guides

| Guide | What you'll learn |
|-------|-------------------|
| [Live Scanning](live-scanning.md) | Consent model, discovery modes, merge semantics, behavioral probe |
| [Remote Scanning](remote-scanning.md) | HTTP/SSE, auth, protocol probes |
| [Static Snapshot](static-snapshot.md) | Offline `tools/list` JSON scanning |
| [Protocol Fuzzing](fuzzing.md) | safe/standard/aggressive levels, probe catalog, CI usage |
| [TypeScript Discovery](typescript-discovery.md) | SDK patterns, Zod mapping, multi-language merge |
| [Config Inventory](inventory.md) | Client paths, JSON schema, cross-server shadowing |
| [Readiness Scanning](readiness.md) | Operational heuristics via `mcts readiness` |

---

## Data flow

```
Static (Py/TS) ──┐
Live probe ──────┼──► MCPServerInfo ──► Analyzers
Fuzz events ─────┤
Inventory ───────┘ (cross-server context)
```

Deep dive: [Architecture — Discovery](../analysis/architecture.md#discovery-layer-discovery)

---

## Planned discovery modes

| Mode | Status | Phase | Notes |
|------|--------|-------|-------|
| Machine-wide scan (all client configs) | Missing | 2 | GAP-006 — no explicit target |
| 12+ agent clients (Gemini, Codex, OpenClaw…) | Partial | 3 | GAP-095 |
| Skills directories + `SKILL.md` | Missing | 2–3 | GAP-029, GAP-099 |
| VS Code workspaceStorage profiles | Missing | 3 | GAP-096 |
| Claude Code project/plugin globs | Missing | 3 | GAP-097 |
| WSL + macOS codesign trust | Missing | 3 | GAP-101–102 |
| GitHub URL shallow-clone target | Missing | 3 | GAP-009 |
| Remote `scan-mcp` manifest pre-check | Partial | 2 | GAP-225 |
| `mcts fuzz --url` remote fuzz | Planned | 2 | GAP-190 |

See [Inventory — planned discovery](inventory.md#planned-discovery) and [Feature Expansion Plan](../more/feature-expansion-plan.md#discovery-13).

---

## Related

- [Getting Started](../get-started/getting-started.md)
- [CLI Reference](../platform/cli.md)
- [Planned discovery modes](#planned-discovery-modes)
- [Documentation index](../index.md)
