# CLI Reference

## `mcpvault scan`

Run a full security scan.

```bash
mcpvault scan <target> [--output report.json] [--fail-on-critical]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write JSON report to file |
| `--fail-on-critical` | Exit code 1 if critical findings exist |

## `mcpvault report`

Generate HTML from a JSON scan report.

```bash
mcpvault report report.json [--output security-report.html]
```

## `mcpvault fuzz` (roadmap)

Fuzz an MCP server with generated attack payloads.

## `mcpvault pentest` (roadmap)

AI-assisted penetration testing agent.

## `mcpvault --version`

Print the installed version.
