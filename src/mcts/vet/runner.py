"""Run package vetting across ecosystems."""

from __future__ import annotations

from mcts.vet.models import VetReport
from mcts.vet.npm import vet_npm
from mcts.vet.oci import vet_oci
from mcts.vet.parse import PackageSpec, parse_package_spec
from mcts.vet.pypi import vet_pypi


def run_vet(spec_text: str) -> VetReport:
    spec = parse_package_spec(spec_text)
    if spec.ecosystem == "pypi":
        return vet_pypi(spec)
    if spec.ecosystem == "npm":
        return vet_npm(spec)
    return vet_oci(spec)


def parse_spec(spec_text: str) -> PackageSpec:
    return parse_package_spec(spec_text)
