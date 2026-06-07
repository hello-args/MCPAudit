## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature / analyzer
- [ ] Breaking change
- [ ] Documentation

## Test plan

- [ ] `uv run pytest`
- [ ] `uv run ruff check src tests`
- [ ] Manual CLI test (if applicable)
  ```bash
  uv run mcts scan examples/vulnerable-mcp-server/server.py
  uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
  uv run mcts report report.json -o security-report.html
  ```

## Checklist

- [ ] CHANGELOG.md updated (if user-facing) — see [Keep a Changelog](../CHANGELOG.md)
- [ ] Tests added or updated
- [ ] No secrets or credentials in code
- [ ] Docs updated if CLI behavior or report output changed — see [docs/](docs/)
