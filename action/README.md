# MCTS GitHub Action

Composite action for running MCTS security scans in CI with JSON, SARIF, and HTML outputs.

**Status:** Ready for `@v1` tag — generates SARIF for Code Scanning; upload via a workflow step with `security-events: write`. Publish with `git tag v1 && git push origin v1` on the default branch.

---

## Usage (local / monorepo)

```yaml
- uses: actions/checkout@v4
- uses: ./action
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: "70"
```

## Usage (after publish)

```yaml
- uses: actions/checkout@v4
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: "70"
```

The action runs `mcts scan`, emits `mcts-report.sarif`, generates HTML via `mcts report`, and uploads JSON/HTML artifacts. Add a separate workflow step to publish SARIF to GitHub Code Scanning (requires `security-events: write`):

```yaml
permissions:
  contents: read
  security-events: write

- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: mcts-report.sarif
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Path to MCP server entrypoint or repo directory |
| `fail-on-critical` | `true` | Fail workflow on critical findings |
| `min-score` | — | Fail if overall score is below threshold (0–100) |

---

## Related

- [Roadmap — GitHub Action](../docs/roadmap.md#2-github-action)
- [CLI Reference](../docs/cli.md)
