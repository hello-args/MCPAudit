# MCP Config Inventory

> [Documentation](../index.md) → [Scanning](README.md)

`mcts inventory` discovers MCP servers configured on the **local machine** by reading known client configuration files. It answers: *which MCP servers are installed, how are they launched, and do tool names collide across servers?*

Optional `--scan` runs a lightweight static discovery pass on each entrypoint to list tool names. Cross-server analysis flags **tool shadowing** when identical tool names appear on different servers — a common agent confusion vector mapped to **MCTS-T-1008**.

**Implementation:** `inventory/discoverers.py`, `inventory/runner.py`, `analyzers/cross_server.py`

Configs with `//` comments or JSON5-style syntax (common in VS Code `settings.json`) are parsed via `discovery/json5_util.py`.

---

## Commands

```bash
# List configured servers (terminal output)
mcts inventory

# Static-scan each entrypoint + export JSON
mcts inventory --scan -o inventory.json

# Theme for saved-notice styling only
mcts inventory --theme minimal -o inventory.json
```

### Exit codes

| Code | When |
|------|------|
| 0 | Success; no critical/high shadow findings |
| 1 | Cross-server shadow findings with **critical** or **high** severity |
| 2 | Theme/usage error |

---

## Supported clients and paths

Platform-specific paths are defined in `CLIENT_PATHS` (`inventory/discoverers.py`). Only **existing** files are read.

### macOS (`darwin`)

| Client | Config path |
|--------|-------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json`, `~/Library/Application Support/Code/User/settings.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

### Linux

| Client | Config path |
|--------|-------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json`, `~/.config/Code/User/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

### Windows (`win32`)

| Client | Config path |
|--------|-------------|
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json`, `~/AppData/Roaming/Code/User/settings.json` |
| Claude Desktop | `~/AppData/Roaming/Claude/claude_desktop_config.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

Client name is inferred from the path string (`cursor`, `claude`, `vscode`, `windsurf`).

---

## Config parsing

MCTS reads JSON config files and extracts `mcpServers` entries:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "uv",
      "args": ["run", "server.py"],
      "env": { "API_KEY": "..." }
    }
  }
}
```

For VS Code, it also supports `mcp.servers` nested under settings JSON when the `mcp` key is present.

Each entry becomes an `InventoryEntry`:

| Field | Description |
|-------|-------------|
| `client` | cursor, claude, vscode, windsurf |
| `server_name` | Key in `mcpServers` |
| `command` | Launch binary |
| `args` | Argument list |
| `env_keys` | Environment variable **names** only (values not exported) |
| `config_path` | Absolute path to source file |
| `tools` | Populated when `--scan` is used |

---

## Terminal output example

```text
MCP inventory — 2 config file(s)
  • cursor
  • claude
  [cursor] my-server (12 tools) — /Users/you/.cursor/mcp.json
  [claude] filesystem — /Users/you/Library/.../claude_desktop_config.json

Cross-server shadowing: 1 finding(s)
  • Tool name collision: read_file
```

---

## JSON export schema

```json
{
  "clients_scanned": ["cursor", "claude"],
  "config_files_found": 2,
  "entries": [
    {
      "client": "cursor",
      "server_name": "my-server",
      "command": "uv",
      "args": ["run", "server.py"],
      "config_path": "/Users/you/.cursor/mcp.json",
      "env_keys": ["API_KEY"],
      "tools": ["read_file", "write_file", "delete_all_users"]
    }
  ],
  "shadow_findings": [
    {
      "title": "Tool name collision: read_file",
      "severity": "high",
      "technique_id": "MCTS-T-1008"
    }
  ]
}
```

---

## `--scan` behavior

When `--scan` is set, `inventory/runner.py` resolves each entrypoint (preferring `.py` paths from `args`) and runs a lightweight static `Scanner` to collect tool names. This does **not** run the full analyzer suite — it is optimized for inventory breadth.

Non-Python entrypoints (Node, Go binaries) may not resolve automatically. Use explicit `mcts scan` with `--command` for those servers.

---

## Cross-server tool shadowing

`CrossServerAnalyzer.analyze_inventory()` builds a map of tool name → list of `(client, server_name)` pairs. When the same name appears on **different** servers:

- Finding severity scales with collision count and client diversity
- Technique ID: **MCTS-T-1008** (Cross-Server Tool Shadowing)
- Mitigations reference agent routing and namespacing guidance

**Why it matters:** LLM agents often select tools by name only. Two servers both exposing `read_file` may cause the agent to invoke the wrong handler — potentially crossing trust boundaries.

During `mcts scan`, the same analyzer can run when inventory context is wired into `Scanner` (future: automatic inventory hook).

---

## Scanning a discovered server

After inventory, run a full security scan:

```bash
# Static scan from config
mcts scan . --config ~/.cursor/mcp.json --server my-server

# Live probe from config
mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --live --i-understand-live-risk
```

See [Live Scanning](live-scanning.md).

---

## Limitations

| Limitation | Detail |
|------------|--------|
| Local configs only | No remote fleet or enterprise MDM discovery |
| Heuristic entrypoint resolution | `--scan` may miss non-Python launch patterns |
| Four clients today | Broader agent support on [roadmap](../more/roadmap.md) — see [Planned discovery](#planned-discovery) |
| No secret values in export | Only `env_keys` names — not values |
| Ephemeral CI runners | GitHub-hosted runners typically have no user MCP configs |

---

## Planned discovery

Competitor audit gaps targeting inventory and config discovery (GAP-095–105, GAP-218–231):

| Capability | Status | Phase | GAP |
|------------|--------|-------|-----|
| 12+ agent clients (Gemini, Codex, OpenClaw, Amazon Q…) | Partial | 3 | GAP-095 |
| VS Code `workspaceStorage` / profiles | Missing | 3 | GAP-096 |
| Claude Code plugin + project-level globs | Missing | 3 | GAP-097 |
| Skills dirs (`.cursor/skills`, etc.) | Missing | 3 | GAP-099 |
| `mcts inventory --skills` | Missing | 2 | GAP-029 |
| Machine-wide scan without explicit target | Missing | 2 | GAP-006 |
| `--scan-all-users` multi-home | Missing | 3 | GAP-021 |
| macOS codesign trust on stdio binaries | Missing | 3 | GAP-101 |
| WSL profile merge | Missing | 3 | GAP-102 |
| Shadow MCP discovery + allowlist | Missing | 2 | GAP-231 |
| CycloneDX AI-BOM export | Missing | 2–3 | GAP-106 |
| Fleet asset prefix / enterprise merge | Missing | 4 | GAP-116 |

Full list: [Feature Expansion Plan — Discovery](../more/feature-expansion-plan.md#discovery-13).

---

## Security note

Inventory reads configuration files that may **reference** secrets via environment variables. MCTS does not print env values in inventory output. Treat exported JSON like any config audit artifact.

---

## Related

- [CLI Reference — mcts inventory](../platform/cli.md#mcts-inventory)
- [Architecture — Inventory](../analysis/architecture.md#inventory-inventory)
- [Threat Taxonomy — MCTS-T-1008](../reporting/taxonomy.md)
- [Live Scanning — config launch](live-scanning.md#from-client-mcp-config)
