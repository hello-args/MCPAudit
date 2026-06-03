# CLI Reference

## `redmcp scan`

Run a full security scan.

```bash
redmcp scan <target> [--output report.json] [--fail-on-critical]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Write JSON report to file |
| `--fail-on-critical` | Exit code 1 if critical findings exist |

## `redmcp report`

Generate HTML from a JSON scan report.

```bash
redmcp report report.json [--output security-report.html]
```

## `redmcp fuzz` (roadmap)

Fuzz an MCP server with generated attack payloads.

## `redmcp pentest` (roadmap)

AI-assisted penetration testing agent.

## `redmcp --version`

Print the installed version.
