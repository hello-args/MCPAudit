# MCTS GitHub Action

Composite action for running MCTS security scans in CI.

**Status:** Scaffold — publishing and SARIF upload planned in [Phase 1](../docs/roadmap.md#phase-1--adoption--live-probing--planned). Full CI guide: [Feature Expansion Plan](../docs/feature-expansion-plan.md#15-ci-scorecard--gates).

---

## Current usage (scaffold)

```yaml
- uses: ./action
  with:
    target: ./server.py
    fail-on-critical: true
```

Or after publish:

```yaml
- uses: MCTS/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
```

---

## Planned inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Path to MCP server entrypoint or repo directory |
| `fail-on-critical` | `true` | Fail workflow on critical findings |
| `min-score` | — | Fail if overall score below threshold |
| `format` | `json` | `json` or `sarif` |
| `upload-sarif` | `false` | Upload SARIF to GitHub Code Scanning |

---

## Planned workflow (Phase 1)

```yaml
name: MCP Security

on: [pull_request]

jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MCTS/MCTS@v1
        with:
          target: ./server.py
          fail-on-critical: true
          min-score: 70
          format: sarif

      - uses: actions/upload-artifact@v4
        with:
          name: mcts-report
          path: |
            mcts-report.json
            mcts-report.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

---

## Related

- [Feature Expansion Plan — CI gates](../docs/feature-expansion-plan.md#15-ci-scorecard--gates)
- [Roadmap — GitHub Action](../docs/roadmap.md#2-github-action)
- [CLI Reference](../docs/cli.md)
