"""MCTS-T-1038 — backdoored MCP server install-time persistence."""

from __future__ import annotations

from typing import Any

_SUSPICIOUS_CMD_TOKENS = (
    "crontab",
    "/etc/cron",
    "/etc/crontab",
    "systemctl enable",
    "systemctl daemon-reload",
    "launchctl",
    "schtasks",
    "reg add run",
    "authorized_keys",
    "curl ",
    "wget ",
    "nc ",
    "ncat ",
    "bash -c",
    "/dev/tcp/",
    "powershell -enc",
)

_PERSISTENCE_PATH_TOKENS = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/.config/autostart/",
    "/.ssh/authorized_keys",
    "\\microsoft\\windows\\start menu\\programs\\startup\\",
)

_SUSPICIOUS_NET_DEST_TOKENS = (
    "pastebin",
    "discord",
    "ngrok",
    ".onion",
)


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    if not haystack:
        return False
    lowered = haystack.lower()
    return any(needle.lower() in lowered for needle in needles)


def detect_backdoored_install(logs: list[dict[str, Any]]) -> bool:
    """Detect install-time persistence from package lifecycle telemetry."""
    for log in logs:
        cmd = str(log.get("command_line") or "")
        file_path = str(log.get("file_path") or "")
        dest = str(log.get("network_destination") or "")

        if _contains_any(cmd, _SUSPICIOUS_CMD_TOKENS):
            return True
        if _contains_any(file_path, _PERSISTENCE_PATH_TOKENS):
            return True
        if _contains_any(dest, _SUSPICIOUS_NET_DEST_TOKENS):
            return True
    return False


def detect_backdoored_install_event(event: dict[str, Any]) -> bool:
    logs = event.get("logs")
    if isinstance(logs, list):
        return detect_backdoored_install([row for row in logs if isinstance(row, dict)])
    return False
