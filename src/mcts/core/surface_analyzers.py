"""Map analyzers to MCP scan surfaces for surface-scoped runs."""

from __future__ import annotations

from mcts.core.config import DEFAULT_SURFACES

PROMPT_INSTRUCTION_ANALYZERS = frozenset(
    {
        "prompt_injection",
        "jailbreak",
        "prompt_defense",
        "metadata_integrity",
        "surface_metadata",
        "skill_md",
        "llm_judge",
        "llm_metadata_triage",
        "line_jumping",
    }
)

TOOL_ANALYZERS = frozenset(
    {
        "permission_analyzer",
        "tool_abuse",
        "schema_surface",
        "command_execution",
        "path_validation",
        "behavioral_static",
        "tool_shadowing",
        "attack_chains",
        "data_leakage",
    }
)

REPO_WIDE_ANALYZERS = frozenset(
    {
        "supply_chain",
        "embedding_secrets",
        "oauth_config",
        "semgrep_sast",
        "sigma_metadata",
        "yara_metadata",
        "npm_audit",
        "vulnerable_package",
        "virustotal",
        "cloud_inspect",
        "cross_server",
        "toxic_flows",
        "metadata_diff",
    }
)


def analyzer_name(analyzer: object) -> str:
    name = getattr(analyzer, "name", None)
    if name:
        return str(name)
    if type(analyzer).__name__ == "AttackChainAnalyzer":
        return "attack_chains"
    return type(analyzer).__name__


def analyzer_allowed_for_surfaces(analyzer: object, surfaces: list[str], *, enabled: bool) -> bool:
    """Return whether *analyzer* should run for the active surface subset."""
    if not enabled:
        return True

    active = {item.strip().lower() for item in surfaces if item.strip()}
    if not active or active == set(DEFAULT_SURFACES):
        return True

    name = analyzer_name(analyzer)
    if name == "runtime_events":
        return bool(active & {"tool", "prompt", "resource", "instruction"})

    if name in PROMPT_INSTRUCTION_ANALYZERS:
        return bool(active & {"prompt", "instruction", "resource"})

    if name in TOOL_ANALYZERS:
        return "tool" in active

    if name in REPO_WIDE_ANALYZERS:
        return "tool" in active

    return "tool" in active
