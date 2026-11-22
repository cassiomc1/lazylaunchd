#!/usr/bin/env python3
"""Build the high-resolution macOS AppIcon.icns for lazylaunchd.

Artwork: a dark midnight-blue squircle with a terminal service list card
(running/warning/failed status dots) and a bright emerald/cyan launch rocket
glyph symbolizing macOS launchd service management.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

try:  # Pillow 10+ moved Resampling constants.
    LANCZOS = Image.Resampling.LANCZOS
except AttributeError:  # pragma: no cover - older Pillow
    LANCZOS = Image.LANCZOS

SIZE = 1024
MARGIN = 82
CORNER_RADIUS = 204
ICON_SIZES = [
    (16, 1),
    (16, 2),
    (32, 1),
    (32, 2),
    (128, 1),
    (128, 2),
    (256, 1),
    (256, 2),
    (512, 1),
    (512, 2),
]


def _gradient() -> Image.Image:
    """Create a smooth midnight-blue/slate diagonal gradient background."""
    scale = 128
    small = Image.new("RGB", (scale, scale))
    pixels = small.load()
    if pixels is None:
        return small.resize((SIZE, SIZE), LANCZOS)
    for y in range(scale):
        for x in range(scale):
            factor = (x * 0.42 + y * 0.58) / scale
            pixels[x, y] = (
                int(13 * (1 - factor) + 24 * factor),
                int(17 * (1 - factor) + 43 * factor),
                int(23 * (1 - factor) + 73 * factor),
            )
    return small.resize((SIZE, SIZE), LANCZOS)


def _squircle_mask() -> Image.Image:
    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [MARGIN, MARGIN, SIZE - MARGIN, SIZE - MARGIN],
        radius=CORNER_RADIUS,
        fill=255,
    )
    return mask


def _draw_terminal_card(draw: ImageDraw.ImageDraw) -> None:
    """Draw the inner terminal service-list card with status indicators."""
    card_box = [176, 200, 848, 796]
    draw.rounded_rectangle(
        card_box,
        radius=56,
        fill=(18, 24, 34, 245),
        outline=(56, 139, 253, 140),
        width=6,
    )

    # Top title bar
    draw.rounded_rectangle(
        [176, 200, 848, 286],
        radius=56,
        fill=(25, 34, 48, 255),
    )
    draw.rectangle([176, 248, 848, 288], fill=(25, 34, 48, 255))
    draw.line([(178, 288), (846, 288)], fill=(48, 54, 61, 255), width=4)

    # Traffic-light status dots (green running, amber warning, red failed)
    dots = [
        (236, 244, (63, 185, 80, 255)),
        (288, 244, (240, 180, 41, 255)),
        (340, 244, (248, 81, 73, 255)),
    ]
    for cx, cy, color in dots:
        draw.ellipse([cx - 14, cy - 14, cx + 14, cy + 14], fill=color)

    # Subtle header pill on right of titlebar
    draw.rounded_rectangle(
        [632, 232, 796, 256],
        radius=12,
        fill=(48, 66, 94, 255),
    )

    # Service rows inside the terminal window
    rows = [
        (356, (63, 185, 80, 255), 510, (121, 192, 255, 220)),
        (456, (63, 185, 80, 255), 460, (139, 148, 158, 210)),
        (556, (248, 81, 73, 255), 420, (248, 129, 122, 225)),
        (656, (240, 180, 41, 255), 370, (139, 148, 158, 180)),
    ]
    for row_y, dot_color, bar_end, bar_color in rows:
        # Row highlight strip
        draw.rounded_rectangle(
            [216, row_y - 30, 808, row_y + 30],
            radius=16,
            fill=(24, 33, 46, 230),
        )
        # Status dot
        draw.ellipse([240, row_y - 14, 268, row_y + 14], fill=dot_color)
        # Label bar
        draw.rounded_rectangle(
            [296, row_y - 11, bar_end, row_y + 11],
            radius=11,
            fill=bar_color,
        )


def _draw_launch_badge(draw: ImageDraw.ImageDraw) -> None:
    """Draw a bright cyan/emerald launch rocket & bolt emblem on the foreground."""
    cx, cy = 698, 646
    r = 166

    # Shadow halo
    draw.ellipse(
        [cx - r - 10, cy - r - 10, cx + r + 10, cy + r + 10],
        fill=(10, 14, 20, 230),
    )
    # Badge circle
    draw.ellipse(
        [cx - r, cy - r, cx + r, cy + r],
        fill=(16, 48, 62, 255),
        outline=(57, 211, 155, 255),
        width=12,
    )

    # Stylized upward rocket / launch chevron + exhaust flame
    rocket_body = [
        (cx, cy - 108),        # nose tip
        (cx + 48, cy - 34),
        (cx + 42, cy + 44),
        (cx + 80, cy + 74),    # right fin
        (cx + 30, cy + 68),
        (cx + 22, cy + 84),
        (cx - 22, cy + 84),
        (cx - 30, cy + 68),
        (cx - 80, cy + 74),    # left fin
        (cx - 42, cy + 44),
        (cx - 48, cy - 34),
    ]
    draw.polygon(rocket_body, fill=(88, 224, 255, 255))

    # Inner highlight stripe on rocket
    draw.polygon(
        [
            (cx, cy - 86),
            (cx + 22, cy - 28),
            (cx + 18, cy + 52),
            (cx - 18, cy + 52),
            (cx - 22, cy - 28),
        ],
        fill=(220, 250, 255, 255),
    )

    # Porthole
    draw.ellipse([cx - 18, cy - 36, cx + 18, cy], fill=(16, 48, 62, 255))
    draw.ellipse([cx - 10, cy - 28, cx + 10, cy - 8], fill=(57, 211, 155, 255))

    # Exhaust flame
    draw.polygon(
        [
            (cx - 18, cy + 86),
            (cx + 18, cy + 86),
            (cx, cy + 132),
        ],
        fill=(255, 176, 32, 255),
    )


def generate_icon(output_icns: Path) -> None:
    """Render the 1024x1024 artwork and compile `output_icns` via `iconutil`."""
    output_icns = output_icns.expanduser().resolve()
    output_icns.parent.mkdir(parents=True, exist_ok=True)

    base = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    base.paste(_gradient(), (0, 0), _squircle_mask())

    draw = ImageDraw.Draw(base)
    draw.rounded_rectangle(
        [MARGIN, MARGIN, SIZE - MARGIN, SIZE - MARGIN],
        radius=CORNER_RADIUS,
        outline=(88, 166, 255, 115),
        width=6,
    )
    _draw_terminal_card(draw)
    _draw_launch_badge(draw)

    iconset_dir = output_icns.parent / f"{output_icns.stem}.iconset"
    if iconset_dir.exists():
        shutil.rmtree(iconset_dir)
    iconset_dir.mkdir(parents=True)

    for size, scale in ICON_SIZES:
        target_size = size * scale
        resized = base.resize((target_size, target_size), LANCZOS)
        filename = f"icon_{size}x{size}@2x.png" if scale == 2 else f"icon_{size}x{size}.png"
        resized.save(iconset_dir / filename)

    if shutil.which("iconutil") is None:
        raise SystemExit("iconutil is required to build an .icns file (macOS only).")

    subprocess.run(
        ["iconutil", "-c", "icns", str(iconset_dir), "-o", str(output_icns)],
        check=True,
    )
    shutil.rmtree(iconset_dir)
    print(f"Icon written: {output_icns}")


if __name__ == "__main__":
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("assets/AppIcon.icns")
    generate_icon(destination)
