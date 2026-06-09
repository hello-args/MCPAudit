"""Shared heuristics for package vetting."""

from __future__ import annotations

import re

from mcts.reporting.models import Severity
from mcts.vet.models import VetFinding

_SUSPICIOUS_TEXT = re.compile(
    r"(?i)\b(curl|wget|webhook|exfil|pastebin|ngrok|ignore previous|override policy|"
    r"postinstall|preinstall|eval\(|/bin/sh|powershell)\b"
)
_SUSPICIOUS_URL = re.compile(r"(?i)(pastebin|ngrok|requestbin|bit\.ly|tinyurl)")

POPULAR_PYPI: tuple[str, ...] = (
    "mcp",
    "fastmcp",
    "anthropic",
    "openai",
    "pydantic",
    "httpx",
    "uvicorn",
    "fastapi",
)

POPULAR_NPM: tuple[str, ...] = (
    "mcp",
    "@modelcontextprotocol/sdk",
    "typescript",
    "axios",
    "express",
)


def typosquat_findings(*, ecosystem: str, name: str) -> list[VetFinding]:
    known = POPULAR_PYPI if ecosystem == "pypi" else POPULAR_NPM
    lowered = name.lower()
    findings: list[VetFinding] = []
    for popular in known:
        if lowered == popular.lower():
            return findings
        distance = _levenshtein(lowered, popular.lower())
        if 0 < distance <= 2:
            findings.append(
                VetFinding(
                    id=f"vet-typosquat-{popular}",
                    title=f"Possible typosquat of {popular!r}",
                    description=f"Package name {name!r} is edit-distance {distance} from a popular package.",
                    severity=Severity.HIGH,
                    recommendation="Verify the package name and publisher before installing.",
                    evidence={"similar_to": popular, "distance": distance},
                )
            )
    return findings


def metadata_text_findings(*, text: str, source: str) -> list[VetFinding]:
    if not text or not _SUSPICIOUS_TEXT.search(text):
        return []
    return [
        VetFinding(
            id=f"vet-suspicious-{source}",
            title=f"Suspicious {source} content",
            description="Metadata contains install-time or exfiltration language.",
            severity=Severity.MEDIUM,
            recommendation="Review package metadata and publisher reputation manually.",
            evidence={"source": source, "snippet": text[:240]},
        )
    ]


def url_findings(urls: dict[str, str]) -> list[VetFinding]:
    findings: list[VetFinding] = []
    for label, url in urls.items():
        if not url:
            continue
        if not url.startswith("https://"):
            findings.append(
                VetFinding(
                    id=f"vet-insecure-url-{label}",
                    title=f"Non-HTTPS project URL ({label})",
                    description=f"Project link uses insecure transport: {url}",
                    severity=Severity.MEDIUM,
                    recommendation="Prefer packages whose metadata links use HTTPS.",
                    evidence={"label": label, "url": url},
                )
            )
        if _SUSPICIOUS_URL.search(url):
            findings.append(
                VetFinding(
                    id=f"vet-suspicious-url-{label}",
                    title=f"Suspicious project URL ({label})",
                    description=f"Metadata links to a high-risk host: {url}",
                    severity=Severity.HIGH,
                    recommendation="Avoid installing until the publisher is verified.",
                    evidence={"label": label, "url": url},
                )
            )
    return findings


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]
