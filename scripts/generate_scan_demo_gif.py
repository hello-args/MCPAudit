#!/usr/bin/env python3
"""Generate docs/assets/scan-demo.gif from canned MCTS scan terminal frames."""

from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:  # pragma: no cover - optional generator dependency
    raise SystemExit("Install pillow to generate the demo GIF: uv run --with pillow ...") from exc

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "scan-demo.gif"

FRAMES = [
    "$ uv run mcts scan examples/vulnerable-mcp-server/server.py",
    "[✓] Discovering tools...",
    "[✓] Mapping permissions...",
    "[✓] Detecting attack chains...",
    "[✓] Generating report...",
    "",
    "==================== MCTS Security Report ====================",
    "Overall Score:   0/100 (CRITICAL)",
    "Risk Index:      100/100",
    "Tools Discovered: 6",
    "",
    "Top Findings:",
    "● CRITICAL Destructive tool: delete_all_users",
    "● CRITICAL Read → exfiltration attack chain possible",
    "● HIGH Command execution capability detected",
]


def _load_font(size: int = 14):
    for name in ("Menlo.ttc", "DejaVuSansMono.ttf", "Courier New.ttf"):
        try:
            return ImageFont.truetype(name, size=size)
        except OSError:
            continue
    return ImageFont.load_default()


def render_frame(lines: list[str], *, width: int = 900, height: int = 520) -> Image.Image:
    image = Image.new("RGB", (width, height), color=(12, 16, 24))
    draw = ImageDraw.Draw(image)
    font = _load_font()
    y = 24
    for line in lines:
        color = (120, 255, 170) if line.startswith("[✓]") else (230, 235, 245)
        if "CRITICAL" in line:
            color = (255, 96, 96)
        draw.text((24, y), line, fill=color, font=font)
        y += 22
    return image


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    images: list[Image.Image] = []
    for index in range(1, len(FRAMES) + 1):
        images.append(render_frame(FRAMES[:index]))
    images[0].save(
        OUTPUT,
        save_all=True,
        append_images=images[1:],
        duration=450,
        loop=0,
        optimize=True,
    )
    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
