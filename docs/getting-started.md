# Getting Started

## Install

```bash
pip install redmcp
# or with uv
uv tool install redmcp
```

## Scan your first server

```bash
redmcp scan ./server.py
```

RedMCP performs static analysis on Python MCP servers, discovering `@tool` decorators and running security analyzers against them.

## Example output

```
────────────────────── RedMCP Security Report ──────────────────────
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

- Save JSON: `redmcp scan ./server.py -o report.json`
- Generate HTML: `redmcp report report.json`
- Add to CI: see `action/action.yml`
