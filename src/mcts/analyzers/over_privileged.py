"""Over-privileged MCP tool abuse detection (MCTS-T-1006)."""

from __future__ import annotations

from typing import Any

_MCP_PARENT_CMD = ("mcp-server", "model-context-protocol", "mcp_server", "mcp_server", "mcp-")

_PRIVILEGE_IMAGES = (
    "/cat",
    "/curl",
    "/wget",
    "/ssh",
    "/sudo",
    "/chmod",
    "/chown",
    "/mount",
    "/umount",
    "/docker",
    "/systemctl",
    "/nc",
    "/netcat",
    "/less",
    "/more",
    "/head",
    "/tail",
    "/socat",
)

_SENSITIVE_CMD = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/root/",
    "/.ssh/",
    "/var/log/",
    "id_rsa",
    "authorized_keys",
    ".env",
    "docker.sock",
    "/proc/self/environ",
    "aws_access_key",
    "secret_key",
    "api_key",
    "/dev/tcp/",
    "http://",
    "https://",
    "ftp://",
    "--data",
    "--upload-file",
    "-e /bin/",
    "reverse",
    "shell",
    "--privileged",
    "-v /:/",
    ":/host",
)


def detect_over_privileged_process(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1006 indicators in process creation telemetry."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False
    if not _is_mcp_parent(log):
        return False
    image = str(log.get("Image", "")).lower()
    command = str(log.get("CommandLine", "")).lower()
    if not any(image.endswith(tool) for tool in _PRIVILEGE_IMAGES):
        return False
    return any(marker in command for marker in _SENSITIVE_CMD)


def _is_mcp_parent(log: dict[str, Any]) -> bool:
    parent_image = str(log.get("ParentImage", "")).lower()
    parent_cmd = str(log.get("ParentCommandLine", "")).lower()
    if any(token in parent_cmd for token in _MCP_PARENT_CMD):
        return True
    if "mcp" in parent_image:
        return True
    return "mcp" in parent_cmd and any(token in parent_cmd for token in ("node", "python"))
