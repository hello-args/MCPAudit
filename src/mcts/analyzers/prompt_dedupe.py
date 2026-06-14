"""Remove duplicate prompt findings reported for identical prompt content."""

from __future__ import annotations

from typing import Any

from mcts.reporting.models import Finding

_PROMPT_SURFACES = frozenset({"prompt", "instruction"})


def dedupe_prompt_findings(findings: list[Finding]) -> list[Finding]:
    """Merge prompt-injection findings that point at the same prompt text."""
    if not any(_dedupe_key(finding) for finding in findings):
        return findings

    kept: list[Finding] = []
    index_by_key: dict[tuple[str, str, str, str, str], int] = {}
    for finding in findings:
        key = _dedupe_key(finding)
        if key is None:
            kept.append(finding)
            continue
        existing_index = index_by_key.get(key)
        if existing_index is None:
            index_by_key[key] = len(kept)
            kept.append(finding)
            continue
        kept[existing_index] = _merge_locations(kept[existing_index], finding)
    return kept


def _dedupe_key(finding: Finding) -> tuple[str, str, str, str, str] | None:
    if finding.analyzer != "prompt_injection":
        return None
    evidence = finding.evidence or {}
    if evidence.get("surface") not in _PROMPT_SURFACES:
        return None
    if not finding.location or not finding.location.file:
        return None
    content_hash = str(evidence.get("content_hash") or "")
    if not content_hash:
        return None
    finding_type = str(evidence.get("type") or "-".join(finding.id.split("-", 2)[:2]))
    field = str(evidence.get("field") or "")
    return finding.analyzer, finding_type, field, content_hash, finding.severity.value


def _merge_locations(existing: Finding, duplicate: Finding) -> Finding:
    evidence = dict(existing.evidence or {})
    locations = _unique_locations(
        [
            _location_row(existing),
            *(evidence.get("also_found_in") or []),
            _location_row(duplicate),
        ]
    )
    if len(locations) > 1:
        evidence["also_found_in"] = locations
    return existing.model_copy(update={"evidence": evidence})


def _location_row(finding: Finding) -> dict[str, Any] | None:
    if not finding.location or not finding.location.file:
        return None
    row: dict[str, Any] = {"file": finding.location.file}
    if finding.location.line is not None:
        row["line"] = finding.location.line
    return row


def _unique_locations(rows: list[Any]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int | None]] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        file = str(row.get("file") or "")
        if not file:
            continue
        line = row.get("line")
        key = (file, line if isinstance(line, int) else None)
        if key in seen:
            continue
        seen.add(key)
        item: dict[str, Any] = {"file": file}
        if key[1] is not None:
            item["line"] = key[1]
        unique.append(item)
    return unique
