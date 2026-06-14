"""Prompt finding dedupe tests."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPPrompt, MCPServerInfo


def _scan_prompts(tmp_path: Path, prompts: list[MCPPrompt]):
    config = ScanConfig(
        target=tmp_path,
        surfaces=["prompt"],
        surface_scoped_analyzers=True,
        analyzers=["prompt_injection"],
        scoring_mode="legacy",
    )
    server = MCPServerInfo(name="test", prompts=prompts)
    return Scanner(config).analyze_server(server)


def test_duplicate_prompt_content_merges_locations(tmp_path: Path) -> None:
    text = "Safe prompt text with hidden marker\u200b.\n"
    skill = tmp_path / "skills" / "deploy" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    agent = tmp_path / "src" / "agent_instructions.py"
    agent.parent.mkdir(parents=True)

    report = _scan_prompts(
        tmp_path,
        [
            MCPPrompt(
                name="deploy",
                description=text,
                source_file=str(skill),
                source_line=1,
                discovered_via="skill-md",
            ),
            MCPPrompt(
                name="agent_instructions",
                description=text,
                source_file=str(agent),
                source_line=4,
                discovered_via="instruction-file",
            ),
        ],
    )

    prompt_findings = [finding for finding in report.findings if finding.analyzer == "prompt_injection"]
    assert len(prompt_findings) == 1
    also_found_in = prompt_findings[0].evidence.get("also_found_in")
    assert also_found_in == [
        {"file": str(skill), "line": 1},
        {"file": str(agent), "line": 4},
    ]


def test_distinct_prompts_in_same_file_are_not_deduped(tmp_path: Path) -> None:
    source = tmp_path / "prompts" / "agent_prompts.md"
    source.parent.mkdir(parents=True)
    prompts = [
        MCPPrompt(
            name="first",
            description="First prompt with hidden marker\u200b.",
            source_file=str(source),
            source_line=1,
        ),
        MCPPrompt(
            name="second",
            description="Second prompt with hidden marker\u200b.",
            source_file=str(source),
            source_line=7,
        ),
    ]

    report = _scan_prompts(tmp_path, prompts)

    prompt_findings = [finding for finding in report.findings if finding.analyzer == "prompt_injection"]
    assert len(prompt_findings) == 2
