"""Consent gate for live MCP probing."""

from __future__ import annotations

import os

LIVE_CONSENT_ENV = "MCTS_LIVE_OK"

CONSENT_MESSAGE = """
Live MCP probing starts a real server subprocess and connects over stdio.
Only use this on servers you trust. Malicious servers may execute code on your host.

Pass --i-understand-live-risk to proceed, or set MCTS_LIVE_OK=1 in CI.
"""


class LiveProbeConsentError(RuntimeError):
    """Raised when live probing is requested without explicit consent."""


def live_consent_granted(*, flag: bool = False) -> bool:
    if flag:
        return True
    return os.environ.get(LIVE_CONSENT_ENV, "").strip() in ("1", "true", "yes")


def require_live_consent(*, flag: bool = False) -> None:
    if not live_consent_granted(flag=flag):
        raise LiveProbeConsentError(CONSENT_MESSAGE.strip())
