"""Exposed MCP endpoint / NeighborJack detection (MCTS-T-1027)."""

from __future__ import annotations

import ipaddress
from typing import Any

_MCP_PATHS = ("/sse", "/tools/list", "/tools/call", "/message", "/ping", "/ws")
_MCP_QUERY_MARKERS = ("transporttype=stdio", "jsonrpc=2.0", "method=tools", "method=initialize")


def detect_exposed_endpoint(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1027 indicators in HTTP access logs."""
    log = event.get("log_entry", event)
    if not isinstance(log, dict):
        return False

    query = str(log.get("c-uri-query", "")).lower()
    if "mcp_proxy_auth_token=" in query:
        return False

    path = str(log.get("c-uri-path", "")).lower()
    host = str(log.get("cs-host", "")).lower()
    client_ip = str(log.get("c-ip", ""))

    if "0.0.0.0" in host and any(marker in path for marker in _MCP_PATHS):
        return True

    if "transporttype=stdio" in query and "command=" in query:
        return True

    if path == "/ws" and str(log.get("cs-upgrade", "")).lower() == "websocket":
        return True

    if not _is_mcp_request(path, query):
        return False

    if _is_private_ip(client_ip):
        if path.startswith("/tools") or "method=tools" in query:
            return False
        return "command=" in query

    return True


def _is_mcp_request(path: str, query: str) -> bool:
    if any(path.startswith(marker) or path == marker.rstrip("/") for marker in _MCP_PATHS):
        return True
    return any(marker in query for marker in _MCP_QUERY_MARKERS)


def _is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    return any(
        addr in network
        for network in (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
    )
