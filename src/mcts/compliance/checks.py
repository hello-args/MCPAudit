"""Compliance checks against security standards."""

from __future__ import annotations

from mcts.reporting.models import Finding, Severity

OWASP_ANALYZER_MAP: dict[str, str] = {
    "prompt_injection": "LLM01 Prompt Injection",
    "metadata_integrity": "LLM01 Prompt Injection",
    "schema_surface": "LLM01 Prompt Injection",
    "data_leakage": "LLM02 Sensitive Information Disclosure",
    "path_validation": "LLM02 Sensitive Information Disclosure",
    "tool_abuse": "LLM04 Model Denial of Service",
    "command_execution": "LLM06 Excessive Agency",
    "permission_analyzer": "LLM06 Excessive Agency",
    "attack_chains": "LLM06 Excessive Agency",
    "cross_server": "LLM06 Excessive Agency",
    "jailbreak": "LLM07 System Prompt Leakage",
}


class ComplianceChecker:
    """Maps findings to OWASP LLM Top 10 coverage gaps (meta-findings only)."""

    def check(self, findings: list[Finding]) -> list[Finding]:
        compliance_findings: list[Finding] = []
        scorable = [f for f in findings if f.analyzer != "compliance"]

        covered = {OWASP_ANALYZER_MAP[f.analyzer] for f in scorable if f.analyzer in OWASP_ANALYZER_MAP}
        expected = set(OWASP_ANALYZER_MAP.values())
        missing = expected - covered

        if missing and not scorable:
            compliance_findings.append(
                Finding(
                    id="compliance-no-findings",
                    analyzer="compliance",
                    title="No scorable findings recorded",
                    description="Scan completed without security findings — verify discovery scope.",
                    severity=Severity.LOW,
                    recommendation="Confirm the target contains MCP tool definitions.",
                )
            )

        critical_count = sum(1 for f in scorable if f.severity == Severity.CRITICAL)
        if critical_count >= 3:
            compliance_findings.append(
                Finding(
                    id="compliance-multiple-critical",
                    analyzer="compliance",
                    title="Multiple critical findings — deployment blocked",
                    description=(
                        f"{critical_count} critical findings exceed recommended deployment threshold."
                    ),
                    severity=Severity.MEDIUM,
                    recommendation="Resolve critical findings before production deployment.",
                    evidence={"critical_count": critical_count, "owasp_gaps": sorted(missing)},
                )
            )

        return compliance_findings
