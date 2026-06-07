"""Prompt injection attack simulator."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.tpa_patterns import (
    find_homoglyphs,
    has_hidden_unicode,
    has_mixed_scripts,
)
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding, Severity, SourceLocation

INSTRUCTION_LIKE = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|system prompt|you must|always|never reveal)\b"
)


class PromptInjectionAnalyzer(BaseAnalyzer):
    """Detects prompt injection surfaces in tool descriptions and handlers."""

    name = "prompt_injection"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            findings.extend(self._analyze_tool(tool))
        return findings

    def _analyze_tool(self, tool: MCPTool) -> list[Finding]:
        findings: list[Finding] = []
        loc = SourceLocation(file=tool.source_file or "", line=tool.source_line)

        for field, text in (("description", tool.description), ("name", tool.name)):
            findings.extend(self._unicode_findings(tool, text, field, loc))
            if field == "description":
                findings.extend(self._description_only_findings(tool, text, loc))

        return findings

    def _unicode_findings(
        self,
        tool: MCPTool,
        text: str,
        field: str,
        loc: SourceLocation,
    ) -> list[Finding]:
        findings: list[Finding] = []
        suffix = f"-{field}" if field != "description" else ""

        if has_hidden_unicode(text):
            findings.append(
                Finding(
                    id=f"inject-hidden-chars-{tool.name}{suffix}",
                    analyzer=self.name,
                    title=f"Hidden Unicode in {tool.name} {field}",
                    description="Tool metadata contains invisible Unicode or tag characters.",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    recommendation="Strip zero-width, bidi override, and Unicode tag characters.",
                    technique_id="MCTS-T-1001",
                    confidence=0.8,
                    location=loc,
                    evidence={"type": "hidden_unicode", "field": field},
                )
            )

        homoglyphs = find_homoglyphs(text)
        if homoglyphs:
            findings.append(
                Finding(
                    id=f"inject-homoglyph-{tool.name}{suffix}",
                    analyzer=self.name,
                    title=f"Homoglyph characters in {tool.name} {field}",
                    description="Tool metadata uses Cyrillic lookalike characters that may spoof names.",
                    severity=Severity.MEDIUM,
                    tool=tool.name,
                    recommendation="Use ASCII-only tool names and descriptions where possible.",
                    technique_id="MCTS-T-1001",
                    confidence=0.75,
                    location=loc,
                    evidence={"homoglyphs": homoglyphs[:5], "field": field},
                )
            )

        if has_mixed_scripts(text):
            findings.append(
                Finding(
                    id=f"inject-mixed-script-{tool.name}{suffix}",
                    analyzer=self.name,
                    title=f"Mixed scripts in {tool.name} {field}",
                    description="Tool metadata mixes Unicode scripts — possible obfuscation.",
                    severity=Severity.MEDIUM,
                    tool=tool.name,
                    recommendation="Normalize tool metadata to a single script/encoding.",
                    technique_id="MCTS-T-1001",
                    confidence=0.65,
                    location=loc,
                    evidence={"type": "mixed_scripts", "field": field},
                )
            )

        return findings

    def _description_only_findings(
        self,
        tool: MCPTool,
        description: str,
        loc: SourceLocation,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if INSTRUCTION_LIKE.search(description):
            findings.append(
                Finding(
                    id=f"inject-instruction-like-{tool.name}",
                    analyzer=self.name,
                    title=f"Instruction-like description on {tool.name}",
                    description="Tool description contains imperative language that may confuse agents.",
                    severity=Severity.MEDIUM,
                    tool=tool.name,
                    recommendation=(
                        "Use neutral, descriptive tool documentation without imperative instructions."
                    ),
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    location=loc,
                    evidence={"type": "instruction_like"},
                )
            )

        if self._description_handler_mismatch(tool):
            findings.append(
                Finding(
                    id=f"inject-desc-mismatch-{tool.name}",
                    analyzer=self.name,
                    title=f"Description/handler mismatch on {tool.name}",
                    description="Tool description claims differ from handler implementation signals.",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    recommendation="Align tool descriptions with actual handler behavior.",
                    technique_id="MCTS-T-1001",
                    confidence=0.7,
                    location=loc,
                    evidence={"type": "description_mismatch"},
                )
            )

        risky_patterns = (
            re.compile(r"\b(secret|password|api[_-]?key|credential|token)\b", re.I),
            re.compile(r"\b(execute|eval|shell|subprocess|os\.system)\b", re.I),
            re.compile(r"\b(admin|superuser|root)\b", re.I),
        )
        if any(pattern.search(description) for pattern in risky_patterns):
            findings.append(
                Finding(
                    id=f"inject-risky-surface-{tool.name}",
                    analyzer=self.name,
                    title=f"High-risk injection surface on {tool.name}",
                    description="Tool exposes sensitive capabilities via description keywords.",
                    severity=Severity.HIGH,
                    tool=tool.name,
                    recommendation="Sanitize tool inputs and enforce instruction boundaries.",
                    technique_id="MCTS-T-1001",
                    confidence=0.6,
                    location=loc,
                    evidence={"type": "risky_keywords"},
                )
            )

        return findings

    def _description_handler_mismatch(self, tool: MCPTool) -> bool:
        snippet = (tool.handler_snippet or "").lower()
        desc = tool.description.lower()
        if not snippet or not desc:
            return False
        claims_safe = any(w in desc for w in ("safe", "read-only", "list only", "view"))
        handler_dangerous = any(
            w in snippet for w in ("subprocess", "os.system", "eval", "delete", "shell=true")
        )
        return claims_safe and handler_dangerous
