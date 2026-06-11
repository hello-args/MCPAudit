# Analysis

> [Documentation](../index.md) → **Analysis**

How MCTS **examines** discovered MCP surfaces and **produces findings**.

---

## Pick a guide

| Question | Read |
|----------|------|
| What does this finding mean? | [Security checks reference](security-checks.md) |
| How does the pipeline work? | [Architecture](architecture.md) |
| How do I add an analyzer? | [Architecture — Extension points](architecture.md#extension-points) or [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Why did my scan score this way? | **[Scoring developer guide](../reporting/scoring-guide.md)** |

---

## Flow (one line)

Discovery → analyzers → dedupe/enrich → score → report

Details: [Architecture — At a glance](architecture.md#at-a-glance)

---

## Related

- [Scanning](../scanning/README.md) — how data is collected first
- [Glossary](../glossary.md)
- [Documentation index](../index.md)
