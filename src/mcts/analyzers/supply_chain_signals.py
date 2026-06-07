"""Supply-chain parity helpers (MCTS-T-1014 / MCTS-T-1015)."""

from __future__ import annotations

import json
import re
from typing import Any

UNPINNED_PATTERN = re.compile(r"(\^|~|\*|latest|>=|<=|>|<)", re.I)
SUSPICIOUS_NPM_SCRIPT = re.compile(r"(postinstall|preinstall|prepare)", re.I)


def detect_supply_chain_manifest(entry: dict[str, Any]) -> bool:
    """Return True when a manifest payload matches supply-chain risk patterns."""
    manifest_type = str(entry.get("manifest_type", "")).lower()
    raw = entry.get("manifest")
    if isinstance(raw, str):
        try:
            manifest = json.loads(raw)
        except json.JSONDecodeError:
            return False
    elif isinstance(raw, dict):
        manifest = raw
    else:
        return False

    saf = str(entry.get("technique_scenario", "")).upper()
    if saf == "MCTS-T-1015":
        return _detect_t1003(manifest_type, manifest)
    return _detect_t1002(manifest_type, manifest)


def _detect_t1002(manifest_type: str, manifest: dict[str, Any]) -> bool:
    if manifest_type == "package.json":
        for section in ("dependencies", "devDependencies"):
            deps = manifest.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for spec in deps.values():
                if isinstance(spec, str) and UNPINNED_PATTERN.search(spec):
                    return True
        return False

    if manifest_type == "requirements.txt":
        for line in manifest.get("lines") or []:
            stripped = str(line).strip()
            if not stripped or stripped.startswith("#"):
                continue
            if UNPINNED_PATTERN.search(stripped) or "==" not in stripped:
                return True
        return False

    if manifest_type == "pyproject.toml":
        for line in manifest.get("lines") or []:
            if UNPINNED_PATTERN.search(str(line)):
                return True
    return False


def _detect_t1003(manifest_type: str, manifest: dict[str, Any]) -> bool:
    if manifest_type == "package.json":
        scripts = manifest.get("scripts") or {}
        if isinstance(scripts, dict):
            for name, body in scripts.items():
                if SUSPICIOUS_NPM_SCRIPT.search(name) and isinstance(body, str) and body.strip():
                    return True
    if manifest_type == "dockerfile":
        for line in manifest.get("lines") or []:
            lowered = str(line).lower()
            if lowered.startswith("from ") and ":latest" in lowered:
                return True
            if lowered.startswith("from ") and "@sha256:" not in lowered and ":" not in lowered.split()[1]:
                return True
    return False
