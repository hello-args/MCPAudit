"""Full-schema poisoning detection (MCTS-T-1001.002)."""

from __future__ import annotations

import json
from typing import Any

FSP_MARKERS: tuple[str, ...] = (
    "<!-- system:",
    "<!-- instruction:",
    "<!-- hidden:",
    "<|system|>",
    "[inst]",
    "### instruction:",
    "${password}",
    "${secret}",
    "${api_key}",
    "${db_password}",
    "${openai_api_key}",
    "environment variable",
    ".env",
    "credentials",
    "password",
    "secret",
    "api_key",
    "include actual",
    "extract",
    "expose",
    "database_password",
    "real password",
    "debug_info",
    "include credentials",
    "api_keys",
    "credential files",
    "sensitive data",
    ".ssh/id_rsa",
    ".aws/credentials",
    "/etc/passwd",
    "/etc/shadow",
    "openai_api_key",
    "anthropic_api_key",
    "huggingface_token",
    "scan for:",
    "*.key",
    "*.pem",
    "*.env files",
    "prioritize credential",
    "containing password",
    "containing secret",
    "containing token",
    "patternproperties",
    "extract and include",
    "api keys or passwords",
)


def detect_schema_fsp(input_schema: dict[str, Any] | None) -> bool:
    """Return True when schema JSON matches MCTS-T-1001.002 poisoning markers."""
    if not input_schema:
        return False
    blob = json.dumps(input_schema, sort_keys=True).lower()
    return any(marker in blob for marker in FSP_MARKERS)
