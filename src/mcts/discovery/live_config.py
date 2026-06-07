"""Resolve live stdio launch configuration."""

from __future__ import annotations

import sys

from mcts.core.config import ScanConfig
from mcts.discovery.config import load_server_from_config
from mcts.probe.models import LiveServerConfig


def resolve_live_config(config: ScanConfig) -> LiveServerConfig:
    if config.config_path and config.config_server:
        return load_server_from_config(config.config_path, config.config_server)

    if config.live_command:
        return LiveServerConfig(
            command=config.live_command,
            args=config.live_args,
            env=config.live_env,
            cwd=str(config.target) if config.target.is_dir() else None,
            server_name=config.config_server or config.target.stem,
        )

    target = config.target
    if target.is_file() and target.suffix == ".py":
        return LiveServerConfig(
            command=sys.executable,
            args=[str(target.resolve())],
            env=config.live_env,
            server_name=target.stem,
        )

    raise ValueError(
        "Live scan requires --command and --args, or --config with --server, "
        "or a Python file target for auto-launch"
    )
