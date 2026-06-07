# CI/CD Integration

MCTS is designed for **local-first pipeline gates** — no cloud API required. Use JSON for artifacts, SARIF for GitHub Advanced Security, and score thresholds to fail builds deterministically.

---

## Quick start (GitHub Actions)

Published composite action:

```yaml
name: MCP Security

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MCP-Audit/MCTS@v1
        with:
          target: ./examples/vulnerable-mcp-server/server.py
          fail-on-critical: true
          min-score: "70"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

The action installs MCTS, runs `mcts scan`, emits `mcts-report.json` and `mcts-report.sarif`, generates `mcts-report.html`, and uploads JSON/HTML as workflow artifacts.

Monorepo / local path: `uses: ./action`

Full action reference: [action/README.md](../action/README.md)

---

## Manual CI commands

### Fail on critical findings

```bash
mcts scan ./server.py --fail-on-critical -o report.json
```

### Score threshold

```bash
mcts scan ./repo/ --min-score 70 --max-critical 0 -o report.json
```

### Category gates

```bash
mcts scan ./repo/ \
  --min-score 70 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15
```

See [scoring-spec.md](scoring-spec.md) for gate semantics.

### SARIF for code scanning

```bash
mcts scan ./server.py --format sarif -o report.sarif
```

Upload to GitHub, GitLab, Azure DevOps, or VS Code Security Panel.

### HTML artifact for reviewers

```bash
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

---

## Live probing in CI

Live scans start a real MCP subprocess. Use only on trusted fixtures or staging servers.

```bash
MCTS_LIVE_OK=1 mcts scan ./server.py --live --no-progress -o report.json
```

Or pass `--i-understand-live-risk`. Requires `pip install .[mcp]` or `uv sync --extra mcp`.

**Fuzz in CI (safe level):**

```bash
MCTS_LIVE_OK=1 mcts fuzz ./server.py --fuzz-level safe --i-understand-live-risk -o fuzz.json
MCTS_LIVE_OK=1 mcts scan ./server.py --runtime-events fuzz.json --no-progress
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed; all gates passed |
| 1 | Gate failure (critical findings, score, category limits) or high/critical fuzz/inventory findings |
| 2 | Usage error, missing consent, probe failure |

---

## Recommended workflow pattern

```yaml
- name: Install MCTS
  run: pip install ".[mcp]"

- name: Static scan
  run: |
    mcts scan ./mcp-server/ \
      --no-progress \
      --min-score 75 \
      --max-critical 0 \
      -o mcts-report.json \
      --format sarif \
      -o mcts-report.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: mcts-report.sarif

- name: Upload reports
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: mcts-reports
    path: |
      mcts-report.json
      mcts-report.sarif
```

Note: when passing both JSON and SARIF to a single scan, run twice or use the GitHub Action (which runs scan + SARIF generation).

---

## Inventory in CI

Audit configured servers on a developer machine or self-hosted runner:

```bash
mcts inventory --scan -o inventory.json
```

Not typically run on ephemeral GitHub-hosted runners (no user MCP configs).

---

## Related

- [CLI Reference](cli.md)
- [Scoring Spec](scoring-spec.md)
- [Roadmap — GitHub Action](roadmap.md#2-github-action)
