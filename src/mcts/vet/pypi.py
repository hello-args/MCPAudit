"""PyPI package vetting."""

from __future__ import annotations

import re

import httpx

from mcts.reporting.models import Severity
from mcts.vet.heuristics import metadata_text_findings, typosquat_findings, url_findings
from mcts.vet.models import VetFinding, VetReport
from mcts.vet.parse import PackageSpec


def _fetch_json(url: str) -> httpx.Response:
    try:
        return httpx.get(url, timeout=20.0, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"PyPI request failed: {exc}") from exc


def _version_sort_key(version: str) -> tuple[tuple[int, int | str], ...]:
    parts = re.findall(r"\d+|[a-zA-Z]+", version)
    return tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)


def _available_version_suggestions(payload: dict, requested_version: str | None) -> list[str]:
    versions = []
    releases = payload.get("releases")
    if isinstance(releases, dict):
        versions.extend(str(version) for version in releases)

    latest = str((payload.get("info") or {}).get("version") or "").strip()
    if latest:
        versions.append(latest)

    normalized_requested = str(requested_version or "").strip()
    unique_versions = []
    seen = set()
    for version in versions:
        normalized = version.strip()
        if not normalized or normalized == normalized_requested or normalized in seen:
            continue
        seen.add(normalized)
        unique_versions.append(normalized)

    unique_versions.sort(key=_version_sort_key, reverse=True)
    return unique_versions[:3]


def _package_not_found_report(spec: PackageSpec) -> VetReport:
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


def _version_not_found_report(spec: PackageSpec, payload: dict) -> VetReport:
    suggestions = _available_version_suggestions(payload, spec.version)
    latest = str((payload.get("info") or {}).get("version") or "").strip() or None

    if suggestions:
        recommendation = f"Try an available version such as {', '.join(suggestions)}."
    elif latest:
        recommendation = f"Try the current latest release {latest!r} instead."
    else:
        recommendation = "Verify the requested version against the versions published on PyPI."

    evidence = {"requested_version": spec.version, "suggestions": suggestions}
    if latest:
        evidence["latest_version"] = latest

    return VetReport(
        ecosystem="pypi",
        package=spec.name,
        version=spec.version,
        verdict="not_found",
        findings=[
            VetFinding(
                id="vet-version-not-found",
                title="Version not found on PyPI",
                description=(
                    f"Package {spec.name!r} exists on PyPI, but version {spec.version!r} was not found."
                ),
                severity=Severity.HIGH,
                recommendation=recommendation,
                evidence=evidence,
            )
        ],
    )


def vet_pypi(spec: PackageSpec) -> VetReport:
    project_url = f"https://pypi.org/pypi/{spec.name}/json"
    url = project_url
    if spec.version:
        url = f"https://pypi.org/pypi/{spec.name}/{spec.version}/json"

    response = _fetch_json(url)

    if response.status_code == 404:
        if spec.version:
            project_response = _fetch_json(project_url)
            if project_response.status_code == 200:
                return _version_not_found_report(spec, project_response.json())
            if project_response.status_code == 404:
                return _package_not_found_report(spec)
            project_response.raise_for_status()

        return _package_not_found_report(spec)

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
