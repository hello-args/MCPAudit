"""Detect repository languages for static MCP discovery."""

from __future__ import annotations

from pathlib import Path

from mcts.core.config import DEFAULT_EXCLUDE_DIRS

DEFAULT_LANGUAGES = ("python", "typescript")

GO_MCP_INDICATORS = (
    "AddTool(",
    "RegisterTool(",
    "github.com/modelcontextprotocol/go-sdk",
    "github.com/mark3labs/mcp-go",
)

RUST_MCP_INDICATORS = (
    "rmcp::",
    "mcp_server::",
    "#[tool",
    "tool_router",
    "CallToolRequest",
    "ListToolsRequest",
)


def detect_repo_languages(
    root: Path,
    *,
    exclude_dirs: frozenset[str] | set[str] | None = None,
) -> set[str]:
    """Infer extra discovery languages from repository contents."""
    if not root.is_dir():
        return set()

    skip = frozenset(exclude_dirs or DEFAULT_EXCLUDE_DIRS)
    detected: set[str] = set()

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if set(rel_parts) & skip:
            continue

        suffix = path.suffix.lower()
        if suffix == ".go" and _file_has_indicators(path, GO_MCP_INDICATORS):
            detected.add("go")
        elif suffix == ".rs" and _file_has_indicators(path, RUST_MCP_INDICATORS):
            detected.add("rust")
        elif path.name == "Cargo.toml" and _file_has_indicators(path, ("rmcp", "mcp_server")):
            detected.add("rust")

    return detected


def resolve_default_languages(
    target: Path,
    *,
    exclude_dirs: frozenset[str] | set[str] | None = None,
) -> list[str]:
    """Return default scan languages plus any detected from the target path."""
    ordered = list(DEFAULT_LANGUAGES)
    if target.is_dir():
        for lang in sorted(detect_repo_languages(target, exclude_dirs=exclude_dirs)):
            if lang not in ordered:
                ordered.append(lang)
    elif target.suffix.lower() == ".go":
        ordered.append("go")
    elif target.suffix.lower() == ".rs":
        ordered.append("rust")
    return ordered


def _file_has_indicators(path: Path, indicators: tuple[str, ...]) -> bool:
    try:
        if path.stat().st_size > 500_000:
            return False
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(indicator in content for indicator in indicators)
