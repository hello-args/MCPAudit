"""Tests for pre-install package vetting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcts.reporting.models import Severity
from mcts.vet.parse import parse_package_spec
from mcts.vet.runner import run_vet


def test_parse_package_spec_pypi() -> None:
    spec = parse_package_spec("pypi:requests@2.31.0")
    assert spec.ecosystem == "pypi"
    assert spec.name == "requests"
    assert spec.version == "2.31.0"


def test_parse_package_spec_pypi_colon_version() -> None:
    spec = parse_package_spec("pypi:requests:2.31.0")
    assert spec.ecosystem == "pypi"
    assert spec.name == "requests"
    assert spec.version == "2.31.0"


def test_parse_package_spec_pypi_double_equals_version() -> None:
    spec = parse_package_spec("pypi:requests==2.31.0")
    assert spec.ecosystem == "pypi"
    assert spec.name == "requests"
    assert spec.version == "2.31.0"


def test_parse_package_spec_npm_scoped() -> None:
    spec = parse_package_spec("npm:@types/node@20.0.0")
    assert spec.ecosystem == "npm"
    assert spec.name == "@types/node"
    assert spec.version == "20.0.0"


def test_parse_package_spec_oci() -> None:
    spec = parse_package_spec("oci:ghcr.io/org/image:1.2.3")
    assert spec.ecosystem == "oci"
    assert spec.name == "ghcr.io/org/image:1.2.3"
    assert spec.version == "1.2.3"


def test_vet_pypi_flags_yanked_release() -> None:
    payload = {
        "info": {
            "name": "demo-package",
            "version": "1.0.0",
            "summary": "Demo package",
            "description": "Safe description",
            "yanked": True,
            "project_urls": {},
        }
    }
    mock_response = MagicMock(status_code=200, json=lambda: payload)
    mock_response.raise_for_status = MagicMock()

    with patch("mcts.vet.pypi.httpx.get", return_value=mock_response):
        report = run_vet("pypi:demo-package")

    assert report.verdict == "fail"
    assert any(f.id == "vet-yanked" for f in report.findings)


def test_vet_pypi_not_found() -> None:
    mock_response = MagicMock(status_code=404)
    with patch("mcts.vet.pypi.httpx.get", return_value=mock_response):
        report = run_vet("pypi:missing-package-xyz")
    assert report.verdict == "not_found"
    assert report.findings[0].severity == Severity.HIGH
    assert report.findings[0].title == "Package not found on PyPI"


def test_vet_pypi_missing_version_suggests_recent_releases() -> None:
    version_response = MagicMock(status_code=404)
    project_payload = {
        "info": {
            "name": "kubernetes",
            "version": "32.0.1",
            "summary": "Kubernetes Python client",
            "description": "Safe description",
            "project_urls": {},
        },
        "releases": {
            "32.0.1": [],
            "31.0.0": [],
            "30.1.0": [],
            "25.0.0": [],
        },
    }
    project_response = MagicMock(status_code=200, json=lambda: project_payload)
    project_response.raise_for_status = MagicMock()

    with patch("mcts.vet.pypi.httpx.get", side_effect=[version_response, project_response]):
        report = run_vet("pypi:kubernetes==25.0.0")

    assert report.verdict == "not_found"
    assert report.findings[0].id == "vet-version-not-found"
    assert report.findings[0].title == "Version not found on PyPI"
    assert "25.0.0" in report.findings[0].description
    assert report.findings[0].evidence["latest_version"] == "32.0.1"
    assert report.findings[0].evidence["suggestions"] == ["32.0.1", "31.0.0", "30.1.0"]
    assert "32.0.1" in report.findings[0].recommendation


def test_vet_npm_flags_lifecycle_script() -> None:
    payload = {
        "description": "Install helper",
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "description": "Install helper",
                "scripts": {"postinstall": "node setup.js"},
            }
        },
    }
    mock_response = MagicMock(status_code=200, json=lambda: payload)
    mock_response.raise_for_status = MagicMock()

    with patch("mcts.vet.npm.httpx.get", return_value=mock_response):
        report = run_vet("npm:demo-helper")

    assert any(f.id == "vet-npm-script-postinstall" for f in report.findings)


def test_vet_oci_unknown_registry() -> None:
    report = run_vet("oci:evil-registry.example/suspicious/image:latest")
    assert any(f.id == "vet-oci-unknown-registry" for f in report.findings)


def test_vet_invalid_spec_raises() -> None:
    with pytest.raises(ValueError, match="pypi:, npm:, or oci:"):
        parse_package_spec("requests")
