"""Agent jailbreak resistance testing."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity


class JailbreakAnalyzer(BaseAnalyzer):
    """Measures agent manipulation surface from tool capabilities."""

    name = "jailbreak"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        score = self._manipulation_score(server.tools)

        if score >= 8:
            severity = Severity.HIGH
        elif score >= 5:
            severity = Severity.MEDIUM
        else:
            return []

        findings.append(
            Finding(
                id="jailbreak-manipulation-surface",
                analyzer=self.name,
                title="Elevated agent manipulation surface",
                description=(
                    f"Weighted manipulation score {score}/10 from tool count, "
                    "execution capabilities, and schema gaps."
                ),
                severity=severity,
                recommendation="Reduce tool count, add schemas, and restrict execution capabilities.",
                technique_id="MCTS-T-1007",
                confidence=0.7,
                evidence={
                    "manipulation_score": score,
                    "tool_count": len(server.tools),
                    "executes_commands": sum(
                        1 for t in server.tools if t.capability and t.capability.executes_commands
                    ),
                },
            )
        )
        return findings

    def _manipulation_score(self, tools: list[MCPTool]) -> int:
        score = 0
        score += min(3, len(tools) // 2)
        for tool in tools:
            cap = tool.capability
            if cap and cap.executes_commands:
                score += 2
            if cap and cap.egresses_network:
                score += 1
            if not tool.input_schema.get("properties"):
                score += 1
        return min(10, score)
