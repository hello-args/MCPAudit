"""Scan configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

DEFAULT_EXCLUDE_DIRS = (
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
)


class ScanConfig(BaseModel):
    """Configuration for a MCTS security scan."""

    target: Path
    output: Path | None = None
    output_format: str = "json"
    fail_on_critical: bool = False
    min_score: int | None = Field(default=None, ge=0, le=100)
    max_critical: int | None = Field(default=None, ge=0)
    enable_jailbreak: bool = True
    enable_attack_chains: bool = True
    timeout_seconds: int = Field(default=120, ge=1)
    theme: str = "cyber"
    no_progress: bool = False
    include_globs: list[str] = Field(default_factory=lambda: ["**/*.py"])
    exclude_globs: list[str] = Field(default_factory=list)
    exclude_dirs: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    max_file_bytes: int = Field(default=500_000, ge=1)
    live: bool = False
    live_command: str | None = None
    live_args: list[str] = Field(default_factory=list)
    live_env: dict[str, str] = Field(default_factory=dict)
    config_path: Path | None = None
    config_server: str | None = None
    live_consent: bool = False
    merge_static_live: bool = True
    fuzz_level: str = "safe"
    fuzz_consent: bool = False
    languages: list[str] = Field(default_factory=lambda: ["python", "typescript"])
    sigma_rules_path: Path | None = None
    baseline_path: Path | None = None
    save_baseline_path: Path | None = None
    semantic_secrets: bool = False
    runtime_events: list[dict[str, Any]] = Field(default_factory=list)
    behavioral_probe: bool = False
    fail_on_category: dict[str, int] = Field(default_factory=dict)
