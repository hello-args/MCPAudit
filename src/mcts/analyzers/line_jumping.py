"""Line jumping / context precedence attacks (MCTS-T-1021)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation

PRIORITY_INSTRUCTIONS: tuple[str, ...] = (
    "system directive",
    "priority_instruction",
    "priority directive",
    "takes precedence",
    "override all",
    "suspend security",
    "disable restrictions",
    "temporarily suspended",
    "bypass all subsequent",
    "ignore any restrictions",
    "security validation mode",
    "authorization checks",
    "admin privilege level",
    "elevated privileges",
)

FAKE_DELIMITERS: tuple[str, ...] = (
    "<!--[system",
    "<!--[priority",
    "[priority_instruction]",
    "[admin_override",
    "[security_bypass]",
    "---[system",
    "---[end system",
    "[context_update]",
    "<|system|>",
    "<|priority|>",
    "[directive",
    "[instruction",
)

CONTEXT_MANIPULATION: tuple[str, ...] = (
    "establish precedence",
    "higher priority than",
    "supersede all",
    "takes priority over",
    "overrides later",
    "ignore subsequent instructions",
    "disregard following rules",
    "preceding all",
    "before any",
    "first priority",
)

SECURITY_BYPASS: tuple[str, ...] = (
    "without additional confirmation",
    "skip validation",
    "bypass authentication",
    "disable authorization",
    "allow full table access",
    "unrestricted access",
    "elevated privileges",
    "admin privilege level",
    "allow full access",
    "grant full permissions",
    "remove restrictions",
    "bypass security",
)

STEALTH_INDICATORS: tuple[str, ...] = (
    "never mention",
    "do not disclose",
    "keep hidden",
    "do not reveal",
    "silently",
    "without notifying",
    "do not inform",
)

TRUSTED_SOURCES = frozenset({"system_prompt", "security_policy", "admin_config"})
EARLY_CONTEXT_THRESHOLD = 100

_EDUCATIONAL_MARKERS: tuple[str, ...] = (
    "security best practices",
    "security documentation",
    "explains how",
    "this section explains",
    "always validate system directive patterns",
)


def detect_line_jumping(
    content: str,
    *,
    context_position: int = 0,
    content_source: str = "",
    authenticated: bool = False,
) -> bool:
    """Detect MCTS-T-1021 line jumping in context or tool metadata text."""
    if not content:
        return False

    lowered = content.lower()
    if content_source in TRUSTED_SOURCES and authenticated:
        return False
    if context_position >= EARLY_CONTEXT_THRESHOLD:
        return False
    if any(marker in lowered for marker in _EDUCATIONAL_MARKERS):
        return False

    spaced_directive = re.sub(r"\s+", "", lowered)
    if "systemdirective" in spaced_directive and "suspend" in spaced_directive:
        return True

    categories = (
        PRIORITY_INSTRUCTIONS,
        FAKE_DELIMITERS,
        CONTEXT_MANIPULATION,
        SECURITY_BYPASS,
        STEALTH_INDICATORS,
    )
    return any(any(pattern in lowered for pattern in group) for group in categories)


class LineJumpingAnalyzer(BaseAnalyzer):
    """Detect line-jumping patterns in tool descriptions (static metadata proxy)."""

    name = "line_jumping"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if not detect_line_jumping(tool.description, context_position=0):
                continue
            findings.append(
                Finding(
                    id=f"line-jump-{tool.name}",
                    analyzer=self.name,
                    title=f"Line jumping pattern on {tool.name}",
                    description=(
                        "Tool metadata attempts to establish precedence over security "
                        "directives (MCTS-T-1021)."
                    ),
                    severity=Severity.HIGH,
                    tool=tool.name,
                    recommendation=(
                        "Strip priority/override language from tool metadata; enforce "
                        "immutable system policy ordering."
                    ),
                    technique_id="MCTS-T-1021",
                    confidence=0.8,
                    location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                    evidence={"type": "line_jumping"},
                )
            )
        return findings
