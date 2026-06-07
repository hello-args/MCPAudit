"""DNS / mDNS poisoning indicators (MCTS-T-1028)."""

from __future__ import annotations

from typing import Any


def detect_dns_poisoning_event(event: dict[str, Any]) -> bool:
    """Detect MCTS-T-1028 indicators in DNS/TLS telemetry events."""
    message = str(event.get("Message", "")).lower()
    event_id = event.get("EventID")
    provider = str(event.get("Provider_Name", ""))

    if event_id == 1014 and provider == "Microsoft-Windows-DNS-Client":
        if "timed out" in message or "dnssec validation failed" in message:
            return True
        if "resolved to known ip" in message:
            return False

    if event_id == 2022 and provider == "Microsoft-Windows-TCPIP":
        if "duplicate arp entry detected" in message:
            return True
        if "arp cache updated" in message:
            return False

    if provider == "Schannel":
        if event_id == 36882 and "untrusted certificate authority" in message:
            return True
        if event_id == 36884 and "does not match the certificate host name" in message:
            return True
        if "tls handshake completed with trusted certificate" in message:
            return False
        if "tls session established, certificate subject validated" in message:
            return False

    if event_id == 9999 and provider == "ODR":
        if "duplicate service registration detected" in message:
            return True
        if "name collision detected" in message:
            return True
        if "service registration refreshed" in message:
            return False

    return False
