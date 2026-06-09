"""npm registry package vetting."""

from __future__ import annotations

import httpx

from mcts.reporting.models import Severity
from mcts.vet.heuristics import metadata_text_findings, typosquat_findings
from mcts.vet.models import VetFinding, VetReport
from mcts.vet.parse import PackageSpec

_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def vet_npm(spec: PackageSpec) -> VetReport:
    encoded = spec.name.replace("/", "%2f")
    url = f"https://registry.npmjs.org/{encoded}"

    try:
        response = httpx.get(url, timeout=20.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"npm registry request failed: {exc}") from exc

    if response.status_code == 404:
        return VetReport(
            ecosystem="npm",
            package=spec.name,
            version=spec.version,
            verdict="not_found",
            findings=[
                VetFinding(
                    id="vet-not-found",
                    title="Package not found on npm",
                    description=f"No npm package matches {spec.name!r}.",
                    severity=Severity.HIGH,
                    recommendation="Verify the package name and registry.",
                )
            ],
        )

    response.raise_for_status()
    payload = response.json()
    version = spec.version or payload.get("dist-tags", {}).get("latest")
    version_meta = (payload.get("versions") or {}).get(version or "", {})
    if not version_meta and version:
        version_meta = (payload.get("versions") or {}).get(version, {})

    findings: list[VetFinding] = []
    findings.extend(typosquat_findings(ecosystem="npm", name=spec.name))

    description = str(version_meta.get("description") or payload.get("description") or "")
    findings.extend(metadata_text_findings(text=description, source="description"))

    scripts = version_meta.get("scripts") or {}
    if isinstance(scripts, dict):
        for script_name in _LIFECYCLE_SCRIPTS:
            body = scripts.get(script_name)
            if isinstance(body, str) and body.strip():
                findings.append(
                    VetFinding(
                        id=f"vet-npm-script-{script_name}",
                        title=f"npm lifecycle script: {script_name}",
                        description="Install-time scripts can execute arbitrary code.",
                        severity=Severity.MEDIUM,
                        recommendation="Review lifecycle scripts before installing.",
                        evidence={"script": body[:240]},
                    )
                )

    verdict = "fail" if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings) else "pass"
    return VetReport(
        ecosystem="npm",
        package=spec.name,
        version=version,
        verdict=verdict,
        findings=findings,
    )
