# MCTS Documentation

**MCTS** (Model Context Threat Scanner) analyzes MCP servers — static analysis, risk scoring, terminal dashboard, and shareable HTML reports.

## Guides

- [Getting Started](getting-started.md) — Install, first scan, HTML dashboard
- [CLI Reference](cli.md) — `scan`, `report`, flags, and planned commands
- [HTML Security Dashboard](html-report.md) — Layout, export, and design system
- [Architecture](architecture.md) — Current and target pipeline, analyzers, reporting

## Planning

- [Feature Expansion Plan](feature-expansion-plan.md) — **Full gap analysis, phased implementation, module layout, build order**
- [Product Roadmap](roadmap.md) — Executive phases from foundation → platform
- [Feature matrix (README)](../README.md#features) — Current module status

## Blog & community

- [Building MCP Security in Public](blog-building-mcp-security-in-public.md) — Honest alpha status, known gaps, and discussion prompts
- [Product overview (promotional)](promotional-article.md) — Shorter introduction for sharing

## Changelog

- [Changelog](../CHANGELOG.md) — User-facing release notes

## Planned documentation

These docs will be added as features ship (see [Feature Expansion Plan — Part 6](feature-expansion-plan.md#part-6--documentation-to-addupdate)):

- `scoring-spec.md` — Open scoring formula and CI gate semantics
- `taxonomy.md` — MCTS-T technique catalog
- `live-scanning.md` — Consent, transports, CI flags
- `inventory.md` — Client config discovery
- `ci-integration.md` — GitHub Action, SARIF upload
- `competitive-positioning.md` — How MCTS differs from other MCP security tools
