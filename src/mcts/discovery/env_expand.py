"""Cross-platform environment variable expansion for MCP config values."""

from __future__ import annotations

import os
import re
import sys

_UNIX_PATTERN = re.compile(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_WIN_PATTERN = re.compile(r"%([^%]+)%")


def expand_value(value: str, mode: str = "auto") -> str:
    """Expand env vars in a single string."""
    platform = _resolve_mode(mode)

    def unix_replace(match: re.Match[str]) -> str:
        key = match.group(1) or match.group(2) or ""
        return os.environ.get(key, match.group(0))

    def win_replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return os.environ.get(key, match.group(0))

    if platform in ("linux", "mac", "auto"):
        value = _UNIX_PATTERN.sub(unix_replace, value)
    if platform in ("windows", "auto"):
        value = _WIN_PATTERN.sub(win_replace, value)
    return value


def expand_mapping(values: dict[str, str], mode: str = "auto") -> dict[str, str]:
    return {k: expand_value(v, mode=mode) for k, v in values.items()}


def expand_args(args: list[str], mode: str = "auto") -> list[str]:
    return [expand_value(a, mode=mode) for a in args]


def _resolve_mode(mode: str) -> str:
    if mode == "off":
        return "off"
    if mode in ("linux", "mac", "windows", "auto"):
        if mode == "auto":
            if sys.platform == "win32":
                return "windows"
            if sys.platform == "darwin":
                return "mac"
            return "linux"
        return mode
    raise ValueError(f"Unknown expand-vars mode {mode!r}")
