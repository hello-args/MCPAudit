"""OCI image reference vetting (metadata-only)."""

from __future__ import annotations

import re

from mcts.reporting.models import Severity
from mcts.vet.models import VetFinding, VetReport
from mcts.vet.parse import PackageSpec

_TRUSTED_REGISTRIES = (
    "docker.io",
    "ghcr.io",
    "gcr.io",
    "registry.k8s.io",
    "public.ecr.aws",
    "quay.io",
)

_REF_PATTERN = re.compile(
    r"^(?:(?P<registry>[\w.-]+(?::\d+)?)/)?(?P<repo>[\w./-]+)(?:(?P<tag>:[\w][\w.-]*)|(?P<digest>@sha256:[a-f0-9]{64}))?$",
    re.I,
)


def vet_oci(spec: PackageSpec) -> VetReport:
    ref = spec.name
    findings: list[VetFinding] = []

    match = _REF_PATTERN.match(ref)
    if not match:
        findings.append(
            VetFinding(
                id="vet-oci-invalid-ref",
                title="Invalid OCI image reference",
                description=f"Could not parse image reference {ref!r}.",
                severity=Severity.HIGH,
                recommendation="Use registry/repo:tag or registry/repo@sha256:digest format.",
            )
        )
        return VetReport(
            ecosystem="oci",
            package=ref,
            version=spec.version,
            verdict="fail",
            findings=findings,
        )

    registry = match.group("registry") or "docker.io"
    if registry not in _TRUSTED_REGISTRIES:
        findings.append(
            VetFinding(
                id="vet-oci-unknown-registry",
                title="Unfamiliar OCI registry",
                description=f"Registry {registry!r} is not in the trusted default list.",
                severity=Severity.MEDIUM,
                recommendation="Verify registry ownership and image signatures before pull.",
                evidence={"registry": registry},
            )
        )

    if not match.group("digest") and not match.group("tag"):
        findings.append(
            VetFinding(
                id="vet-oci-floating-tag",
                title="Floating OCI tag",
                description="Image reference has no explicit tag or digest.",
                severity=Severity.LOW,
                recommendation="Pin images by digest for reproducible installs.",
            )
        )

    verdict = "fail" if any(f.severity in {Severity.CRITICAL, Severity.HIGH} for f in findings) else "pass"
    return VetReport(
        ecosystem="oci",
        package=ref,
        version=spec.version,
        verdict=verdict,
        findings=findings,
    )
