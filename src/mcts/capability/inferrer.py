"""Rule-based capability inference for MCP tools."""

from __future__ import annotations

import re

from mcts.mcp.models import CapabilityProfile, MCPTool

READ_HINTS = re.compile(r"\b(read|fetch|get|list|query|load|open|email)\b", re.I)
EGRESS_HINTS = re.compile(r"\b(send|post|upload|webhook|http|export|request|fetch\s+url)\b", re.I)
EXEC_HINTS = re.compile(r"\b(exec|execute|run|shell|subprocess|system|eval|command)\b", re.I)
SENSITIVE_HINTS = re.compile(r"\b(password|token|credential|secret|key|auth|env)\b", re.I)
MUTATE_HINTS = re.compile(r"\b(delete|write|update|create|drop|remove|destroy|insert)\b", re.I)

DANGEROUS_CALLS = re.compile(
    r"\b(subprocess|os\.system|eval|exec|httpx|requests|urllib|webhook|"
    r"child_process|execSync|spawnSync|spawn)\b",
    re.I,
)


def infer_capability(tool: MCPTool) -> CapabilityProfile:
    """Derive capability dimensions from tool metadata and handler snippet."""
    haystack = f"{tool.name} {tool.description}"
    schema_text = " ".join(tool.input_schema.get("properties", {}).keys())
    haystack = f"{haystack} {schema_text}"
    snippet = tool.handler_snippet or ""

    profile = CapabilityProfile(
        reads_untrusted_input=bool(READ_HINTS.search(haystack) or "path" in haystack.lower()),
        accesses_sensitive_data=bool(SENSITIVE_HINTS.search(haystack)),
        mutates_state=bool(MUTATE_HINTS.search(haystack)),
        egresses_network=bool(EGRESS_HINTS.search(haystack) or DANGEROUS_CALLS.search(snippet)),
        executes_commands=bool(EXEC_HINTS.search(haystack) or DANGEROUS_CALLS.search(snippet)),
    )

    if "run_shell" in tool.name or "shell" in tool.name.lower():
        profile.executes_commands = True
    if "webhook" in tool.name.lower() or "send_" in tool.name:
        profile.egresses_network = True
    if "read_file" in tool.name or "get_env" in tool.name:
        profile.reads_untrusted_input = True
        profile.accesses_sensitive_data = True

    return profile
