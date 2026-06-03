# Getting Started

## Install

```bash
pip install mcpvault
# or with uv
uv tool install mcpvault
```

## Scan your first server

```bash
mcpvault scan ./server.py
```

MCPVault performs static analysis on Python MCP servers, discovering `@tool` decorators and running security analyzers against them.

## Example output

```
────────────────────── MCPVault Security Report ──────────────────────
Target: examples/vulnerable-mcp-server/server.py
Overall Score: 42/100

        Findings by Severity
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ Critical │     3 │
│ High     │     4 │
...
```

## Next steps

- Save JSON: `mcpvault scan ./server.py -o report.json`
- Generate HTML: `mcpvault report report.json`
- Add to CI: see `action/action.yml`
