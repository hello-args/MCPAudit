# Live MCP Probing

MCTS can connect to a **real stdio MCP server** to enrich tool schemas, list prompts/resources, and read server instructions — then merge with static analysis.

## Consent

Live probing **starts a subprocess** and connects over MCP stdio. Only use on servers you trust.

```bash
# Interactive — explicit flag
mcts scan ./server.py --live --i-understand-live-risk

# CI — environment variable
MCTS_LIVE_OK=1 mcts scan ./server.py --live
```

Fuzzing uses the same consent gate. Aggressive fuzz additionally requires `--i-understand-fuzz-risk`.

---

## Usage

### Auto-launch Python entrypoint

```bash
mcts scan examples/live-mcp-server/server.py --live --i-understand-live-risk
```

MCTS runs `python server.py` (or resolves from config) and merges live schemas with static analysis when source is available.

### Custom launch command

```bash
mcts scan ./server.py --live --i-understand-live-risk \
  --command uv --args run,server.py
```

### From client config

```bash
mcts scan . --live --i-understand-live-risk \
  --config ~/.cursor/mcp.json --server my-server
```

Use `.` as the target when scanning purely from config.

---

## Install

Live probing requires the optional `mcp` extra:

```bash
uv sync --extra mcp
```

---

## Discovery modes

| Mode | `discovery_mode` | When |
|------|------------------|------|
| Static (default) | `static` | Regex + AST (Python) or pattern match (TS/JS) |
| Live | `live` | MCP `list_tools` / `list_prompts` / `list_resources` |
| Merged | `merged` | `--live` with existing static tools — richest schema wins |
| Empty | `empty` | Missing target or config-only with no local source |

Implementation: `discovery/live.py`, `discovery/merge.py`, `probe/session.py`.

---

## Runtime events & behavioral probe

Live scans automatically attach runtime telemetry for `RuntimeEventsAnalyzer`:

- **Live metadata events** — tool/prompt/resource listings from the probe session
- **Behavioral probe** — multi-turn MCTS-T-1026 patterns; enabled by default with `--live`, or explicitly via `--behavioral-probe`

Pre-recorded or fuzz-generated events can be supplied:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [Protocol Fuzzing](fuzzing.md) and [Architecture — Runtime telemetry](architecture.md).

---

## TypeScript / config-only servers

Non-Python servers without local source need `--config` or `--command` to launch:

```bash
mcts scan . --config ~/.cursor/mcp.json --server node-server \
  --live --i-understand-live-risk
```

Static TS discovery still runs when source files are present in the target path. See [typescript-discovery.md](typescript-discovery.md).

---

## Limitations (alpha)

- **Stdio only** — SSE/HTTP transports planned
- **Read-only probe** — `list_*` methods; does not call tools during scan (use `mcts fuzz` for controlled invocation)
- **Consent required** — no silent subprocess spawn

---

## Related

- [CLI Reference — scan flags](cli.md#mcts-scan)
- [CI Integration — MCTS_LIVE_OK](ci-integration.md)
- [Architecture — Probe layer](architecture.md#probe-layer-probe)
