"""PyPI package vetting."""

from __future__ import annotations

import httpx

from mcts.reporting.models import Severity
from mcts.vet.heuristics import metadata_text_findings, typosquat_findings, url_findings
from mcts.vet.models import VetFinding, VetReport
from mcts.vet.parse import PackageSpec


def vet_pypi(spec: PackageSpec) -> VetReport:
    url = f"https://pypi.org/pypi/{spec.name}/json"
    if spec.version:
        url = f"https://pypi.org/pypi/{spec.name}/{spec.version}/json"

    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"PyPI request failed: {exc}") from exc

    if response.status_code == 404:
        return VetReport(
            ecosystem="pypi",
            package=spec.name,
            version=spec.version,
            verdict="not_found",
            findings=[
                VetFinding(
                    id="vet-not-found",
                    title="Package not found on PyPI",
                    description=f"No PyPI project matches {spec.name!r}.",
                    severity=Severity.HIGH,
                    recommendation="Verify the package name and index URL.",
                )
            ],
        )

    response.raise_for_status()
    payload = response.json()
    info = payload.get("info") or {}
    version = spec.version or info.get("version")

    findings: list[VetFinding] = []
    findings.extend(typosquat_findings(ecosystem="pypi", name=spec.name))

    summary = str(info.get("summary") or "")
    description = str(info.get("description") or "")
    findings.extend(metadata_text_findings(text=f"{summary}\n{description}", source="description"))

    project_urls = info.get("project_urls") or {}
    if isinstance(project_urls, dict):
        findings.extend(url_findings({str(k): str(v) for k, v in project_urls.items()}))

    if info.get("yanked"):
        findings.append(
            VetFinding(
                id="vet-yanked",
                title="Yanked PyPI release",
                description=f"Version {version} is marked yanked on PyPI.",
                severity=Severity.HIGH,
                recommendation="Do not install yanked releases; pick a maintained version.",
                evidence={"version": version, "yanked_reason": info.get("yanked_reason")},
            )
        )

    verdict = "fail" if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings) else "pass"
    return VetReport(
        ecosystem="pypi",
        package=spec.name,
        version=version,
        verdict=verdict,
        findings=findings,
    )
