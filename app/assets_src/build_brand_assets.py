"""Generate placeholder branding assets for RioBoilerplate.

Produces three files under ``app/app/assets/``:

  - ``favicon.ico``  -- multi-resolution ICO (16, 32, 48).
  - ``logo.png``     -- 256x256 PNG used as ``rio.App(icon=...)``.
  - ``og_image.png`` -- 1200x630 PNG used in ``og:image`` / ``twitter:image``
    meta tags.

The colors below mirror the dark theme in ``app/app/theme.py``. Update both
files together when rebranding.

Usage (from the outer ``app/`` directory containing ``rio.toml``)::

    python assets_src/build_brand_assets.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ASSETS_DIR = Path(__file__).resolve().parent.parent / "app" / "assets"
WORDMARK = "RioBoilerplate"
MONOGRAM = "RB"

# Mirror of DARK_THEME colors from app/app/theme.py (HSV -> sRGB 8-bit).
# Keep these in sync when rebranding.
PRIMARY_COLOR_RGB = (191, 128, 255)      # rio.Color.from_hsv(0.75, 0.5, 1)
BACKGROUND_COLOR_DARK_RGB = (3, 1, 5)     # rio.Color.from_hsv(0.75, 0.9, 0.02)
WHITE = (255, 255, 255)


def _font(size: int) -> ImageFont.ImageFont:
    """Load a bold sans font, falling back to PIL's default if unavailable."""
    for candidate in ("DejaVuSans-Bold.ttf", "DejaVuSans.ttf"):
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        # Pillow < 10 doesn't accept size= for the default font.
        return ImageFont.load_default()


def _draw_monogram_tile(size: int) -> Image.Image:
    """Render the ``RB`` monogram on a dark rounded tile with accent border."""
    radius = max(4, size // 6)
    border_width = max(1, size // 32)

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle(
        (0, 0, size - 1, size - 1),
        radius=radius,
        fill=BACKGROUND_COLOR_DARK_RGB + (255,),
        outline=PRIMARY_COLOR_RGB + (255,),
        width=border_width,
    )

    font = _font(int(size * 0.5))
    draw.text(
        (size // 2, size // 2),
        MONOGRAM,
        font=font,
        fill=WHITE + (255,),
        anchor="mm",
    )
    return img


def build_favicon() -> Path:
    sizes = (16, 32, 48)
    images = [_draw_monogram_tile(s) for s in sizes]
    out = ASSETS_DIR / "favicon.ico"
    images[0].save(
        out,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    return out


def build_logo() -> Path:
    out = ASSETS_DIR / "logo.png"
    _draw_monogram_tile(256).save(out, format="PNG")
    return out


def build_og_image() -> Path:
    width, height = 1200, 630
    canvas = Image.new(
        "RGBA", (width, height), BACKGROUND_COLOR_DARK_RGB + (255,)
    )
    draw = ImageDraw.Draw(canvas)

    tile_size = 360
    tile = _draw_monogram_tile(tile_size)
    tile_x = 96
    tile_y = (height - tile_size) // 2
    canvas.alpha_composite(tile, (tile_x, tile_y))

    word_x = tile_x + tile_size + 64
    font = _font(96)
    draw.text(
        (word_x, height // 2),
        WORDMARK,
        font=font,
        fill=WHITE + (255,),
        anchor="lm",
    )

    out = ASSETS_DIR / "og_image.png"
    canvas.convert("RGB").save(out, format="PNG")
    return out


def main() -> None:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    favicon = build_favicon()
    logo = build_logo()
    og = build_og_image()
    print(f"Wrote {favicon}")
    print(f"Wrote {logo}")
    print(f"Wrote {og}")


if __name__ == "__main__":
    main()
