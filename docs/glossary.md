# Glossary

> [Documentation](index.md) → **Glossary**

Plain-language definitions for terms used throughout MCTS documentation. If you see an unfamiliar acronym or concept, start here.

---

## Core concepts

| Term | What it means |
|------|---------------|
| **MCP** | **Model Context Protocol** — an open standard that lets AI assistants (like Claude or Cursor) connect to external tools and data sources through small server programs called MCP servers. |
| **MCP server** | A program that exposes **tools** (actions the AI can call), **prompts** (reusable templates), and **resources** (files or data the AI can read). Example: a server that lets an AI query a database or edit files. |
| **MCP client** | The application that connects to MCP servers — for example Cursor, Claude Desktop, VS Code, or Windsurf. Clients read config files that list which servers to launch. |
| **Tool** | A callable action an AI agent can invoke through MCP. Each tool has a name, description, and input schema (JSON Schema defining its parameters). |
| **MCTS** | **Model Context Threat Scanner** — a security tool that analyzes MCP servers for vulnerabilities before you deploy them. Think of it as a linter or security scanner, but built specifically for MCP. |

---

## What MCTS checks

| Term | What it means |
|------|---------------|
| **Finding** | A security issue MCTS detected — for example, a tool that can delete all users, or a description that tries to trick the AI. Each finding has a severity (Critical, High, Medium, Low). |
| **Analyzer** | An automated check that looks for a specific type of problem. MCTS runs 20+ analyzers by default (30+ with optional flags). Examples: permission checks, secret detection, attack chain detection, Semgrep SAST, LLM triage. |
| **Attack chain** | A sequence of tool calls that together create a serious risk — for example, one tool reads sensitive data and another sends it over the network. |
| **Tool shadowing** | When two different MCP servers expose a tool with the same name. The AI may call the wrong server, leading to confusion or abuse. |
| **Description poisoning** | Malicious or misleading text in a tool's description that tries to manipulate the AI into unsafe behavior. |
| **Rug pull** | When a server's advertised tools change between scans — for example, a benign tool is replaced with a destructive one after the user approved it. |

---

## Scan modes

| Term | What it means |
|------|---------------|
| **Static scan** | MCTS reads your source code (Python or TypeScript) without running the server. Fast, safe, and works offline. This is the default mode. |
| **Live probe** | MCTS starts your MCP server as a subprocess and asks it what tools it exposes at runtime. Requires explicit consent (`--i-understand-live-risk`). |
| **Remote scan** | MCTS connects to a hosted MCP server over HTTP or SSE instead of reading local source code. |
| **Snapshot scan** | MCTS analyzes a pre-exported JSON file of tool metadata — useful in air-gapped environments with no network access. |
| **Fuzzing** | MCTS sends test messages to a live server to check how it handles malformed or unexpected input. Default level is read-only and safe. |
| **Inventory** | MCTS reads MCP config files on your machine (12+ agent clients) and lists which servers are installed. Can scan skills with `--skills`. |
| **Machine-wide scan** | `mcts scan --machine-wide` — scan all MCP servers discovered in local client configs without specifying a target path. |
| **Package vetting** | `mcts vet pypi:` / `npm:` / `oci:` — pre-install checks on packages before adding them to an agent environment. |
| **Pentest mode** | `mcts pentest` — structured report combining static recon, attack-chain review, and optional safe fuzz. |
| **MCP server mode** | `mcts-mcp` — run MCTS as an MCP server so IDE agents can call scan tools programmatically. |

---

## Scores and reports

**Start here:** [Scoring developer guide](reporting/scoring-guide.md) — explains the two engines, which metric to use, and CI flags.

| Term | What it means |
|------|---------------|
| **Legacy overall score** | `score.overall` — 0–100, **higher is better**. `--min-score` gates this. |
| **Absolute risk** | `score_v2.absolute_risk` — integer, **higher is worse**. v2 headline metric. |
| **Benchmark security score** | `score_v2.security_score` — 0–100 vs corpus, **higher is better**. Not the same as legacy overall. |
| **Risk level** | `score_v2.risk_level` — `low` / `medium` / `high` / `critical`. |
| **Risk index** | `score.risk_index` — legacy linear 0–100, higher is worse. |
| **scoring_mode** | `both` (default), `v2`, or `legacy`. |
| **Severity** | Critical / High / Medium / Low on each finding. |
| **SARIF** | Standard format for Code Scanning; optional `mcts/scoreV2` run properties. |
| **HTML dashboard** | Shareable report from `mcts report`. |

---

## Taxonomy and standards

| Term | What it means |
|------|---------------|
| **MCTS-T-*** | MCTS technique IDs — unique labels for threat types (e.g. `MCTS-T-1003` = command execution). Every finding can reference one. |
| **MCTS-M-*** | MCTS mitigation IDs — recommended fixes linked to specific techniques. |
| **OWASP LLM Top 10** | A standard list of the most critical security risks for LLM applications. MCTS maps findings to these categories for compliance reporting. |
| **Sigma rules** | YAML-based detection rules used in security monitoring. MCTS includes bundled rules that match against tool metadata. |
| **Semgrep SAST** | Optional static analysis via `--semgrep` — runs bundled Semgrep rules (Python, JS/TS, Java) against the scan target. Requires the `semgrep` CLI on PATH. |
| **LLM metadata triage** | Optional `--llm-triage` analyzer that classifies MCP metadata as malicious, safe, or suspect using an LLM (requires `MCTS_LLM_API_KEY`). |
| **Toxic flow** | Cross-server capability combination where multiple tools together create elevated risk (W015–W020 issue codes). Enable with `--full-toxic-flows`. |
| **SKILL.md** | Agent skill definition files analyzed by `skill_md` (W007–W014). Discovered on `mcts scan` (repo `skills/`, `**/SKILL.md`) and `mcts inventory --skills` (agent config paths). |
| **Instruction discovery** | Default static-scan behavior that loads prompt/instruction content from repository markdown (`SKILL.md`, `*prompt*.md`, `system_prompt.md`) into MCP prompt/instruction surfaces. Disable with `--no-discover-instructions`. |

---

## Technical terms

| Term | What it means |
|------|---------------|
| **stdio** | Standard input/output — how MCTS talks to a local MCP server by launching it as a subprocess and communicating over pipes. |
| **JSON-RPC** | The message format MCP uses for requests and responses between client and server. |
| **JSON Schema** | A standard for describing the shape of JSON data — used to define tool input parameters. |
| **CI gate** | A check that fails the build (exit code 1) when thresholds are not met — legacy (`--min-score`, `--fail-on-category`) or v2 (`--max-absolute-risk`, `--min-security-score`, `--max-risk-level`, `--min-category-score-v2`). |
| **Readiness** | Operational checks separate from security — whether a server is production-ready (logging, error handling, etc.). Run with `mcts readiness`. |

---

## Related

- [Documentation index](index.md)
- [Getting Started](get-started/getting-started.md)
- [Architecture](analysis/architecture.md)
