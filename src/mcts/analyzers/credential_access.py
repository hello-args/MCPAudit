"""Sensitive credential file access detection (MCTS-T-1024)."""

from __future__ import annotations

SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".gcloud/application_default_credentials.json",
    ".azure/",
    ".docker/config.json",
    ".kube/config",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".gem/credentials",
    "serviceaccount.json",
    "terraform.rc",
)

LEGITIMATE_DOC_MARKERS: tuple[str, ...] = (
    "readme.md",
    "/docs/",
    "/src/app.js",
    "/src/",
)


def detect_credential_file_access(*, tool_name: str, file_path: str) -> bool:
    """Return True when a file tool accesses known credential store paths."""
    del tool_name
    if not file_path:
        return False
    lowered = file_path.lower().replace("\\", "/")
    if any(marker in lowered for marker in LEGITIMATE_DOC_MARKERS):
        return False
    return any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)
