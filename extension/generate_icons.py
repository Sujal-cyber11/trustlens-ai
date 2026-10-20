"""Generates simple shield PNG icons (16x16, 48x48, 128x128) in green, amber, red, and grey for the MV3 extension."""
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw

ICON_DIR = Path(__file__).resolve().parent / "icons"

COLORS: dict[str, tuple[int, int, int]] = {
    "green": (16, 185, 129),
    "amber": (245, 158, 11),
    "red": (239, 68, 68),
    "grey": (100, 116, 139),
}

SIZES: tuple[int, ...] = (16, 48, 128)


def make_icon(color_name: str, rgb: tuple[int, int, int], size: int) -> None:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    pad = max(1, size // 12)
    border = max(1, size // 16)
    draw.ellipse(
        [pad, pad, size - pad - 1, size - pad - 1],
        fill=(15, 23, 42, 255),
        outline=rgb + (255,),
        width=border,
    )
    cx = size / 2.0
    top_y = size * 0.22
    mid_y = size * 0.32
    low_y = size * 0.62
    bot_y = size * 0.78
    left_x = size * 0.27
    right_x = size * 0.73
    in_left = size * 0.31
    in_right = size * 0.69

    draw.polygon(
        [
            (cx, top_y),
            (right_x, mid_y),
            (in_right, low_y),
            (cx, bot_y),
            (in_left, low_y),
            (left_x, mid_y),
        ],
        fill=rgb + (255,),
    )
    out_path = ICON_DIR / f"icon_{color_name}_{size}.png"
    img.save(str(out_path), format="PNG")


def main() -> None:
    ICON_DIR.mkdir(parents=True, exist_ok=True)
    for name, rgb in COLORS.items():
        for sz in SIZES:
            make_icon(name, rgb, sz)
    # Default icon set (green)
    for sz in SIZES:
        make_icon("default", COLORS["green"], sz)


if __name__ == "__main__":
    main()