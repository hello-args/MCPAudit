# CLI Reference

**Planned commands and flags:** see [Feature Expansion Plan — Part 4](feature-expansion-plan.md#part-4--phased-implementation). Status in [Roadmap](roadmap.md).

---

## `mcts scan`

Run a full security scan.

```bash
mcts scan <target> [--output report.json] [--fail-on-critical] [--theme cyber]
```

| Flag | Status | Description |
|------|--------|-------------|
| `--output`, `-o` | ✅ | Write JSON report to file |
| `--fail-on-critical` | ✅ | Exit code 1 if critical findings exist |
| `--theme` | ✅ | Terminal theme: `cyber`, `minimal`, `github` |
| `--no-progress` | ✅ | Skip pre-report progress animation |
| `--format` | 📋 | `json` (default), `sarif` |
| `--min-score` | 📋 | Exit 1 if overall score below threshold |
| `--max-critical` | 📋 | Exit 1 if critical count exceeds limit |
| `--live` | 📋 | Connect to running server via MCP stdio |
| `--command`, `--args` | 📋 | Spawn command for live probe |
| `--config`, `--server` | 📋 | Scan server entry from client MCP config |
| `--i-understand-live-risk` | 📋 | Skip consent prompt (CI only) |
| `--record-baseline` | 📋 | Save tool description/schema hashes |
| `--check-baseline` | 📋 | Diff against baseline (rug-pull detection) |
| `--profile` | 📋 | Policy profile: `strict`, `balanced`, `dev` |
| `--llm-review` | 📋 | Opt-in LLM finding review (requires API key) |

`<target>` today: path to a Python MCP server entrypoint. **Planned:** directory (repo scan), config path.

### Scoring output

Each scan prints:

- **Overall Score** — security score (higher is better), exponential decay on weighted findings
- **Risk Index** — raw risk capped at 100 (higher is worse)
- **Scoring basis** — severity counts used (compliance meta-findings excluded)

**Planned:** per-category scorecard in terminal (matches HTML dashboard bars).

JSON reports include `score.overall`, `score.risk_index`, `score.raw_risk`, and `score.basis`.

---

## `mcts report`

Generate a **premium HTML security dashboard** from JSON scan output.

```bash
mcts report report.json [--output security-report.html] [--theme cyber]
```

| Flag | Description |
|------|-------------|
| `--output`, `-o` | HTML report path (default: `security-report.html`) |
| `--theme` | Terminal theme for the success message only |

See [HTML Security Dashboard](html-report.md).

**Planned dashboard sections:** Capability Matrix, Technique Map (`MCTS-T-*`), real trend from scan history.

---

## `mcts inventory` (📋 Planned)

Discover MCP servers configured on this machine.

```bash
mcts inventory
mcts inventory --scan
mcts inventory --scan --server filesystem
mcts inventory --json
```

Supports Cursor, Claude Desktop, VS Code (extensible discoverers). Optional `--skills` in Phase 3.

---

## `mcts audit-config` (📋 Planned)

Static review of `mcpServers` JSON without LLM agent tool invocation.

```bash
mcts audit-config ~/.cursor/mcp.json
mcts audit-config ./claude_desktop_config.json --probe
```

---

## `mcts fuzz` (📋 Planned)

Protocol-level probing against a live MCP server. Stub today.

```bash
mcts fuzz <target> --live --command uv --args run,server.py
mcts fuzz <target> --fuzz-level safe|standard|aggressive
```

Default: read-only (handshake + list). Requires consent or `--i-understand-live-risk`.

---

## `mcts simulate` (📋 Planned)

Active attack-path simulation (Phase 2). See [Roadmap § Attack Simulation](roadmap.md#phase-2--differentiation--future).

---

## `mcts pentest` (📋 Planned)

AI-assisted penetration testing agent (Phase 3). Stub today.

---

## `mcts vet` (📋 Planned)

Pre-install package vetting (Phase 3).

```bash
mcts vet pypi:mcp-server-foo
mcts vet npm:@scope/mcp-server
```

---

## `mcts trend` (📋 Planned)

Show score history for a target from `.mcts/history/`.

---

## `mcts badge` (📋 Planned)

Generate README certification SVG from scan JSON.

---

## `mcts serve` (📋 Planned)

Local REST API for pipeline integration (optional `api` extra).

---

## `mcts --version`

Print the installed version.

---

## CI examples

**Today:**

```bash
mcts scan ./server.py --fail-on-critical -o report.json
```

**Planned:**

```bash
mcts scan ./server.py -o report.sarif --format sarif --min-score 70
```

GitHub Action: see [Roadmap — GitHub Action](roadmap.md#2-github-action) and `action/action.yml`.

Full CI guide (planned): `docs/ci-integration.md`.
