# Relationship to MCTS and MCP Threat Scanners

> For line-by-line analyzer mapping, pattern diffs, coverage matrix, and a prioritized adoption checklist, see **[08 — Script-to-Script Comparison with MCTS](./08-script-to-script-comparison-with-mcts.md)**.

## Fundamental Distinction

| Dimension | SAF-MCP | MCTS / MCP Scanners |
|-----------|---------|-------------------------|
| **What it is** | Threat intelligence framework | Automated security scanner |
| **Primary output** | Technique IDs, mitigations, Sigma YAML | Findings, scores, HTML/JSON reports |
| **Execution** | Static git repository | CLI connecting to MCP servers / source |
| **Answers** | "What attacks exist and how do they work?" | "Does my deployment exhibit this risk?" |
| **Maintainer model** | OpenSSF community SIG | Project-specific maintainers |

SAF-MCP and MCTS are **complementary**, not competing in the same product category. SAF-MCP is closer to MITRE ATT&CK; MCTS is closer to a SAST/DAST tool for MCP artifacts.

## Ecosystem Position

```
                    ┌─────────────────────┐
                    │     SAF-MCP         │
                    │  (Threat taxonomy)  │
                    └──────────┬──────────┘
                               │ informs rules & severity
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
   ┌───────────┐        ┌─────────────┐       ┌─────────────┐
   │  MCTS │        │  MCP-Scan   │       │ Cisco MCP   │
   │           │        │ (Invariant) │       │ Scanner     │
   └───────────┘        └─────────────┘       └─────────────┘
         │                     │                     │
         └─────────────────────┴─────────────────────┘
                               │
                               ▼
                    Findings mapped to SAF-T* / SAF-M*
                    (manual or automated taxonomy bridge)
```

SAF-MCP explicitly references **Invariant MCP-Scan** in SAF-T1001 as an operational tool for TPA detection — acknowledging that frameworks need scanners to enforce their guidance.

## Technique Overlap with Common Scanner Findings

The following mapping connects SAF-MCP techniques to categories MCTS and peer scanners typically detect. This is indicative, not exhaustive — exact rule-to-technique mapping depends on MCTS's internal taxonomy.

### Initial Access & Tool Metadata

| SAF-MCP Technique | Scanner-relevant pattern | MCTS relevance |
|-------------------|-------------------------|-------------------|
| SAF-T1001 Tool Poisoning Attack | Hidden instructions in tool descriptions/schemas | Core MCTS target — tool description analysis |
| SAF-T1001.002 Full-Schema Poisoning | Poisoned parameter names, defaults, enums | Schema-level static analysis |
| SAF-T1008 Tool Shadowing | Cross-server tool name collisions | Multi-server config scanning |
| SAF-T1201 MCP Rug Pull | Time-delayed tool definition changes | Requires diff/monitoring over time |
| SAF-T1205 Persistent Tool Redefinition | Mutating tool metadata across restarts | Version pinning / integrity checks (SAF-M-2) |

### Execution & Injection

| SAF-MCP Technique | Scanner-relevant pattern |
|-------------------|-------------------------|
| SAF-T1101 Command Injection | Unsanitized shell execution in server code |
| SAF-T1102 Prompt Injection | Instruction injection via MCP content vectors |
| SAF-T1105 Path Traversal via File Tool | Relative path abuse in file tools |
| SAF-T1109 Debugging Tool Exploitation | MCP Inspector CVE-2025-49596 class |
| SAF-T1112 Sampling Request Abuse | `sampling/createMessage` misuse |

### OAuth & Token Security

| SAF-MCP Technique | Scanner-relevant pattern |
|-------------------|-------------------------|
| SAF-T1007 OAuth Authorization Phishing | Malicious OAuth flows |
| SAF-T1009 Authorization Server Mix-up | Look-alike AS domains |
| SAF-T1306 Rogue Authorization Server | Attacker-controlled AS minting super-tokens |
| SAF-T1307 Confused Deputy | Token forwarded across user contexts |
| SAF-T1308 Token Scope Substitution | Insufficient scope validation |

### Supply Chain

| SAF-MCP Technique | Scanner-relevant pattern |
|-------------------|-------------------------|
| SAF-T1002 Supply Chain Compromise | Backdoored packages |
| SAF-T1003 Malicious MCP-Server Distribution | Trojanized Docker/npm packages |
| SAF-T1006 User-Social-Engineering Install | Risk awareness (human factor) |
| SAF-T1111 AI Agent CLI Weaponization | Postinstall script + AI CLI abuse |

### AI-Specific / Advanced

| SAF-MCP Technique | Scanner-relevant pattern |
|-------------------|-------------------------|
| SAF-T1603 System Prompt Disclosure | Conversational extraction (behavioral) |
| SAF-T2106 Context Memory Poisoning | Vector store contamination |
| SAF-T2107 AI Model Poisoning | Training data contamination |
| SAF-T3001 RAG Backdoor | Covert triggers in RAG pipeline |

## Mitigation → Scanner Feature Mapping

SAF-MCP mitigations describe controls that scanners partially automate:

| SAF-MCP Mitigation | Scanner operationalization |
|--------------------|---------------------------|
| SAF-M-10 Automated Scanning | **Core scanner function** (MCTS, MCP-Scan) |
| SAF-M-4 Unicode Sanitization | Static pattern detection in tool metadata |
| SAF-M-6 Tool Registry Verification | Allowlist / provenance checks |
| SAF-M-24 SBOM Generation | Supply-chain scanning modules |
| SAF-M-37 Metadata Sanitization | Pre-deployment linting |
| SAF-M-38 Schema Validation | JSON Schema analysis |
| SAF-M-45 Manifest Signing | Signature verification (if implemented) |

Scanners implement **detective** layers (SAF-M-10, M-11 analogs); **architectural** layers (SAF-M-1 CaMeL) require host application changes beyond scanning.

## What SAF-MCP Provides That Scanners Don't

1. **Stable technique IDs** for compliance reporting (`SAF-T1001` in audit trails)
2. **MITRE ATT&CK bridge** for enterprise SOC integration
3. **Attack flow narratives** with incident timelines for threat modeling
4. **Mitigation playbooks** (`SAF-M-*`) with architectural guidance
5. **Research bibliography** per technique for security training
6. **Sub-technique granularity** (FSP, rug pulls, cross-tool poisoning)
7. **Community governance** via OpenSSF SIG for taxonomy evolution

## What Scanners Provide That SAF-MCP Doesn't

1. **Automated assessment** of live MCP configs and servers
2. **Pass/fail gates** for CI/CD pipelines
3. **Risk scores and HTML dashboards** (MCTS HTML report)
4. **Multi-engine composition** (regex + LLM + behavioral + YARA)
5. **Reproducible findings** on specific artifacts
6. **Client config discovery** (Cursor, Claude Desktop paths)

## Using SAF-MCP to Improve MCTS

### 1. Taxonomy enrichment

Map MCTS finding categories to `SAF-T*` IDs in reports:

```
Finding: Hidden Unicode in tool description
  → SAF-T1001.001 (Description-Based Poisoning)
  → MITRE T1195 (Supply Chain Compromise)
  → Mitigations: SAF-M-4, SAF-M-5, SAF-M-7
```

### 2. Detection rule cross-check

Compare MCTS rules against SAF-MCP Sigma patterns in `detection-rule.yml` files:

- Identify coverage gaps (techniques with Sigma but no MCTS rule)
- Import test fixtures from `test-logs.json` for regression tests
- Run `test_detection_rule.py` logic as reference for wildcard handling

### 3. Remediation text

Link MCTS HTML report remediation sections to upstream mitigation dossiers:

```
Recommended controls: SAF-M-2 (Cryptographic Integrity), SAF-M-6 (Registry Verification)
See: https://github.com/SAF-MCP/saf-mcp/tree/main/mitigations/SAF-M-6
```

### 4. Roadmap prioritization

SAF-MCP tactic distribution shows where MCP threat density is highest:

- **Initial Access (9) + Execution (10) + Privilege Escalation (9)** = 28 techniques
- Prioritize MCTS engine development for TPA, prompt injection, OAuth, and cross-server escalation

### 5. Threat intelligence feed

Monitor SAF-MCP Version History and SIG meetings for new techniques (e.g., SAF-T1112 Sampling Request Abuse, SAF-T1111 AI CLI Weaponization) to add scanner rules before wide exploitation.

## Competitive Landscape Summary

| Project | Type | SAF-MCP relationship |
|---------|------|---------------------|
| **SAF-MCP** | Threat framework | Taxonomy source |
| **MCTS** | MCP security scanner | Operationalizes framework threats |
| **Invariant MCP-Scan** | MCP scanner/proxy | Explicitly cited in SAF-T1001 |
| **Cisco MCP Scanner** | Multi-engine scanner | Overlapping technique coverage |
| **MCPSafetyScanner** | LLM agent auditor | Maps to Discovery/Execution techniques |
| **agent-security-scanner-mcp** | Agent MCP server + SAST | Rule-based detection of MCP manifest issues |

SAF-MCP is the **shared vocabulary layer**; scanners compete on detection engines, UX, CI integration, and reporting — not on defining what MCP threats are called.

## MCTS Integration (shipped)

MCTS uses a **first-party taxonomy** — not upstream ID fields on findings:

| MCTS component | Integration |
|----------------|-------------|
| Finding model | `technique_id` (`MCTS-T-*`), `mitigation_ids` (`MCTS-M-*`) |
| HTML / SARIF | Links to `docs/taxonomy.md` via `mitigation_urls.py` |
| Rule engine | Bundled `metadata_rules.json` + optional `--sigma-rules-path` |
| Test suite | `tests/fixtures/regression/MCTS-T-*/` + `regression_harness.py` (34 IDs, ≥80% CI) |
| Docs / roadmap | Upstream comparison in competitor docs only; product docs use MCTS IDs |

See **[08 — Script-to-Script Comparison](./08-script-to-script-comparison-with-mcts.md)** for the full coverage matrix and informal upstream cross-reference table (research use only).
