# Contributing to MCTS

Thank you for helping make MCP security testing accessible to everyone.

## Getting Started

1. Fork and clone the repository
2. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
3. Run `uv sync --all-extras`
4. Install pre-commit hooks: `pre-commit install`

## Development Workflow

```bash
# Run tests
uv run pytest

# Lint & format
uv run ruff check .
uv run ruff format src tests

# Try the CLI locally
uv run mcts scan examples/vulnerable-mcp-server/server.py

# Generate the HTML security dashboard
uv run mcts scan examples/vulnerable-mcp-server/server.py -o report.json
uv run mcts report report.json -o security-report.html
```

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Add tests for new behavior
- Update `CHANGELOG.md` under `[Unreleased]` for user-facing changes
- Follow existing code style (ruff enforces this in CI)

## Branch Protection

Pull requests to `main` require the **test** CI check to pass.

### Enable on GitHub (one-time, repo admin)

**Option A — Script**

```bash
./scripts/enable-branch-protection.sh MCTS/MCTS
```

**Option B — GitHub UI**

1. Go to **Settings → Rules → Rulesets → New branch ruleset**
2. Target: default branch (`main`)
3. Add rule: **Require status checks to pass**
4. Required check: `test`
5. Save and enable enforcement

The ruleset definition lives in `.github/rulesets/main.json`.

## Planning & roadmap

Before large features, read:

- [Feature Expansion Plan](docs/feature-expansion-plan.md) — gap analysis, implementation how-to, module layout
- [Product Roadmap](docs/roadmap.md) — phased deliverables and success criteria

Pick a phase item and open a [feature request](https://github.com/MCTS/MCTS/issues/new?template=feature_request.yml) or Discussion to align on design.

## Adding a New Analyzer

1. Create a module under `src/mcts/analyzers/`
2. Subclass `BaseAnalyzer` and implement `analyze()`
3. Register it in `src/mcts/core/scanner.py`
4. Add benchmark fixture in `examples/bench/` when applicable (see Feature Expansion Plan § 1.7)
5. Assign `technique_id` (`MCTS-T-*`) when taxonomy module exists
6. Add tests under `tests/`

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Questions?

Open a [GitHub Discussion](https://github.com/MCTS/MCTS/discussions) or [issue](https://github.com/MCTS/MCTS/issues).
