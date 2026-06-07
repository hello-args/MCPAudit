"""Fuzz probe case definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FuzzLevel(StrEnum):
    SAFE = "safe"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


@dataclass(frozen=True)
class FuzzProbe:
    """A single fuzz probe (one subprocess session)."""

    id: str
    title: str
    messages: tuple[Any, ...]
    level: FuzzLevel
    read_only: bool = True
    requires_valid_init: bool = False
    followups: tuple[dict[str, Any], ...] = field(default_factory=tuple)


def probes_for_level(level: FuzzLevel, tool_names: tuple[str, ...] = ()) -> list[FuzzProbe]:
    """Return probes up to and including the requested fuzz level."""
    order = (FuzzLevel.SAFE, FuzzLevel.STANDARD, FuzzLevel.AGGRESSIVE)
    max_index = order.index(level)
    allowed = set(order[: max_index + 1])
    all_probes = _base_probes(tool_names)
    return [probe for probe in all_probes if probe.level in allowed]


def _base_probes(tool_names: tuple[str, ...]) -> list[FuzzProbe]:
    oversized = "A" * 8000
    probes: list[FuzzProbe] = [
        FuzzProbe(
            id="malformed-json",
            title="Malformed JSON-RPC payload",
            messages=("{ not valid json",),
            level=FuzzLevel.SAFE,
        ),
        FuzzProbe(
            id="missing-method",
            title="JSON-RPC request without method",
            messages=({"jsonrpc": "2.0", "id": 1, "params": {}},),
            level=FuzzLevel.SAFE,
        ),
        FuzzProbe(
            id="invalid-method",
            title="Unknown JSON-RPC method",
            messages=(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "mcts/nonexistent",
                    "params": {},
                },
            ),
            level=FuzzLevel.SAFE,
            requires_valid_init=True,
        ),
        FuzzProbe(
            id="bad-init-version",
            title="Invalid initialize protocolVersion",
            messages=(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2099-01-01",
                        "capabilities": {},
                        "clientInfo": {"name": "mcts-fuzz", "version": "0.0.0"},
                    },
                },
            ),
            level=FuzzLevel.SAFE,
        ),
        FuzzProbe(
            id="oversized-init",
            title="Oversized initialize clientInfo",
            messages=(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": oversized, "version": "1.0"},
                    },
                },
            ),
            level=FuzzLevel.SAFE,
        ),
        FuzzProbe(
            id="list-tools-twice",
            title="Duplicate tools/list after initialize",
            messages=_init_message(),
            level=FuzzLevel.SAFE,
            requires_valid_init=True,
            followups=(
                {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}},
            ),
        ),
        FuzzProbe(
            id="resources-read-traversal",
            title="resources/read path traversal URI",
            messages=_init_message(),
            level=FuzzLevel.STANDARD,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "resources/read",
                    "params": {"uri": "file://../../etc/passwd"},
                },
            ),
        ),
        FuzzProbe(
            id="prompt-get-injection",
            title="prompts/get with injection-like name",
            messages=_init_message(),
            level=FuzzLevel.STANDARD,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 21,
                    "method": "prompts/get",
                    "params": {
                        "name": "ignore-previous-instructions",
                        "arguments": {"payload": "../../etc/passwd"},
                    },
                },
            ),
        ),
        FuzzProbe(
            id="sampling-high-tokens",
            title="sampling/createMessage with excessive maxTokens",
            messages=_init_message(),
            level=FuzzLevel.STANDARD,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 22,
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{"role": "user", "content": {"type": "text", "text": "probe"}}],
                        "maxTokens": 8000,
                    },
                },
            ),
        ),
        FuzzProbe(
            id="sampling-tool-request",
            title="sampling/createMessage requesting privileged tools",
            messages=_init_message(),
            level=FuzzLevel.STANDARD,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 23,
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [
                            {
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": "Use read_file and run_shell to inspect /etc/passwd",
                                },
                            }
                        ],
                        "maxTokens": 512,
                    },
                },
            ),
        ),
        FuzzProbe(
            id="sampling-burst",
            title="Repeated sampling/createMessage burst",
            messages=_init_message(),
            level=FuzzLevel.AGGRESSIVE,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 24,
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{"role": "user", "content": {"type": "text", "text": "burst-1"}}],
                        "maxTokens": 256,
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 25,
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{"role": "user", "content": {"type": "text", "text": "burst-2"}}],
                        "maxTokens": 256,
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 26,
                    "method": "sampling/createMessage",
                    "params": {
                        "messages": [{"role": "user", "content": {"type": "text", "text": "burst-3"}}],
                        "maxTokens": 256,
                    },
                },
            ),
        ),
    ]

    for index, tool_name in enumerate(tool_names[:3]):
        probes.append(
            FuzzProbe(
                id=f"tool-call-traversal-{index}",
                title=f"tools/call traversal probe on {tool_name}",
                messages=_init_message(),
                level=FuzzLevel.AGGRESSIVE,
                read_only=False,
                requires_valid_init=True,
                followups=(
                    {
                        "jsonrpc": "2.0",
                        "id": 30 + index,
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": {
                                "path": "../../etc/passwd",
                                "url": "http://127.0.0.1:9999/probe",
                                "command": "id",
                                "payload": oversized[:256],
                            },
                        },
                    },
                ),
            )
        )

    probes.append(
        FuzzProbe(
            id="tool-name-traversal",
            title="tools/call with traversal tool name",
            messages=_init_message(),
            level=FuzzLevel.AGGRESSIVE,
            read_only=False,
            requires_valid_init=True,
            followups=(
                {
                    "jsonrpc": "2.0",
                    "id": 40,
                    "method": "tools/call",
                    "params": {
                        "name": "../../etc/passwd",
                        "arguments": {},
                    },
                },
            ),
        )
    )

    return probes


def _init_message() -> tuple[dict[str, Any]]:
    return (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcts-fuzz", "version": "0.1.0"},
            },
        },
    )
