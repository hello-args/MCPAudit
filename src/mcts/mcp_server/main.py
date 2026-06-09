"""Console entry point for mcts-mcp."""

from __future__ import annotations

import sys


def run() -> None:
    try:
        from mcts.mcp_server.server import create_server
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc

    app = create_server()
    app.run(transport="stdio")


if __name__ == "__main__":
    run()
