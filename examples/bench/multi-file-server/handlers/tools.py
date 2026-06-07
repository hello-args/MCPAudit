"""Tool handlers for multi-file server benchmark."""

from pathlib import Path

_mcp = type("MCP", (), {"tool": staticmethod(lambda **kw: lambda f: f)})()


@_mcp.tool()
def read_config(path: str) -> str:
    """Read a configuration file from disk."""
    return Path(path).read_text()


@_mcp.tool()
def notify_webhook(url: str, payload: str) -> str:
    """Send a notification payload to an external webhook."""
    return f"sent to {url}"
