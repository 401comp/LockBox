"""Generate resources/lockbox.icns from a padlock+vault glyph, using only PIL."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

HERE = Path(__file__).resolve().parent


def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Rounded-rect background — deep blue → violet gradient (fake via layers).
    r = int(size * 0.22)
    d.rounded_rectangle(
        [0, 0, size - 1, size - 1],
        radius=r,
        fill=(34, 47, 96, 255),
    )
    # Softer highlight top
    hl = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hl)
    hd.rounded_rectangle(
        [0, 0, size - 1, int(size * 0.55)],
        radius=r,
        fill=(84, 96, 168, 120),
    )
    hl = hl.filter(ImageFilter.GaussianBlur(size * 0.02))
    img = Image.alpha_composite(img, hl)
    d = ImageDraw.Draw(img)

    # Padlock body
    body_w = int(size * 0.52)
    body_h = int(size * 0.36)
    body_x = (size - body_w) // 2
    body_y = int(size * 0.48)
    body_r = int(body_w * 0.14)
    d.rounded_rectangle(
        [body_x, body_y, body_x + body_w, body_y + body_h],
        radius=body_r,
        fill=(245, 220, 120, 255),
        outline=(140, 110, 40, 255),
        width=max(2, size // 128),
    )

    # Shackle
    sh_w = int(body_w * 0.62)
    sh_x = (size - sh_w) // 2
    sh_top = int(size * 0.22)
    sh_bot = body_y + int(size * 0.02)
    sh_thick = max(4, int(size * 0.055))
    # Outer arc
    d.arc(
        [sh_x, sh_top, sh_x + sh_w, sh_top + (sh_bot - sh_top) * 2],
        start=180,
        end=360,
        fill=(210, 210, 220, 255),
        width=sh_thick,
    )
    # Legs
    d.rectangle(
        [sh_x, sh_top + (sh_bot - sh_top), sh_x + sh_thick, sh_bot],
        fill=(210, 210, 220, 255),
    )
    d.rectangle(
        [sh_x + sh_w - sh_thick, sh_top + (sh_bot - sh_top), sh_x + sh_w, sh_bot],
        fill=(210, 210, 220, 255),
    )

    # Keyhole
    kx = size // 2
    ky = body_y + int(body_h * 0.42)
    kr = max(3, int(size * 0.035))
    d.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill=(70, 55, 20, 255))
    d.polygon(
        [
            (kx - kr // 2, ky),
            (kx + kr // 2, ky),
            (kx + kr, ky + int(kr * 2.4)),
            (kx - kr, ky + int(kr * 2.4)),
        ],
        fill=(70, 55, 20, 255),
    )
    return img


def main() -> int:
    sizes = [16, 32, 64, 128, 256, 512, 1024]
    iconset = HERE / "lockbox.iconset"
    iconset.mkdir(exist_ok=True)
    for s in sizes:
        img = draw_icon(s)
        img.save(iconset / f"icon_{s}x{s}.png")
        if s <= 512:
            img2 = draw_icon(s * 2)
            img2.save(iconset / f"icon_{s}x{s}@2x.png")

    icns = HERE / "lockbox.icns"
    # iconutil is macOS-only; fall back to writing PNG if unavailable.
    try:
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(icns)],
            check=True,
        )
        print(f"wrote {icns}")
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"iconutil failed ({exc}); PNGs left in {iconset}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
