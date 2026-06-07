"""Fuzz runner orchestration."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from mcts.core.config import ScanConfig
from mcts.discovery.live_config import resolve_live_config
from mcts.fuzz.classifier import classify_response, finding_from_classification
from mcts.fuzz.payloads import FuzzLevel, probes_for_level
from mcts.fuzz.transport import run_probe_messages
from mcts.probe.consent import require_live_consent
from mcts.probe.session import probe_stdio
from mcts.reporting.models import Finding


@dataclass
class FuzzResult:
    findings: list[Finding] = field(default_factory=list)
    probes_run: int = 0
    level: FuzzLevel = FuzzLevel.SAFE


class FuzzRunner:
    """Run safe read-only MCP protocol fuzz probes against a stdio server."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def run(self) -> FuzzResult:
        return asyncio.run(self.run_async())

    async def run_async(self) -> FuzzResult:
        require_live_consent(flag=self.config.live_consent)
        live_config = resolve_live_config(self.config)
        level = FuzzLevel(self.config.fuzz_level)

        if level == FuzzLevel.AGGRESSIVE and not self.config.fuzz_consent:
            raise ValueError(
                "Aggressive fuzz may invoke tools/call. Pass --i-understand-fuzz-risk to proceed."
            )

        tool_names: tuple[str, ...] = ()
        if level != FuzzLevel.SAFE:
            try:
                server = await probe_stdio(live_config, timeout_seconds=min(self.config.timeout_seconds, 30))
                tool_names = tuple(tool.name for tool in server.tools)
            except Exception:
                tool_names = ()

        probes = probes_for_level(level, tool_names)
        findings: list[Finding] = []
        seen: set[str] = set()

        for probe in probes:
            response_text, process_exited = await run_probe_messages(
                live_config,
                probe.messages,
                timeout_seconds=min(self.config.timeout_seconds, 15),
                followups=probe.followups,
            )
            classified = classify_response(probe, response_text, process_exited=process_exited)
            if classified is None:
                continue
            finding = finding_from_classification(probe, classified)
            if finding.id in seen:
                continue
            seen.add(finding.id)
            finding.evidence["response_excerpt"] = response_text[:500]
            findings.append(finding)

        return FuzzResult(findings=findings, probes_run=len(probes), level=level)
