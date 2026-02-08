import rio

# Primary colors - purple accent
PRIMARY_COLOR = rio.Color.from_hsv(0.75, 0.5, 1)
SECONDARY_COLOR = rio.Color.from_hsv(0.75, 1, 1)

# Background colors - very dark purple (almost black with purple tint)
# Using lower HSV value to compensate for Oklab brightness
BACKGROUND_COLOR_DARK = rio.Color.from_hsv(0.75, 0.9, 0.02)  # Very dark purple
BACKGROUND_COLOR_LIGHT = rio.Color.from_hsv(0.75, 0.0, 0.95)  # Almost white (gray)

# For backwards compatibility - the app now only uses dark theme
BACKGROUND_COLOR = BACKGROUND_COLOR_DARK


def shade_color(base_color: rio.Color, factor: float) -> rio.Color:
    """
    Shades the given color by the specified factor.
    
    - factor < 1: Darkens the color by mixing it with black.
    - factor > 1: Lightens the color by mixing it with white.
    """
    def clamp(v: float) -> float:
        """Ensures the value stays within the 0.0 to 1.0 range."""
        return max(0.0, min(1.0, v))
    
    # Use srgb for consistent color manipulation
    r, g, b = base_color.srgb
    opacity = base_color.opacity  # Preserve original opacity
    
    if factor < 1:
        # Darken by mixing with black
        r *= factor
        g *= factor
        b *= factor
    else:
        # Lighten by mixing with white
        lighten_ratio = factor - 1
        r = r + (1.0 - r) * lighten_ratio
        g = g + (1.0 - g) * lighten_ratio
        b = b + (1.0 - b) * lighten_ratio
    
    # Clamp the values to ensure they are within the valid range
    r, g, b = clamp(r), clamp(g), clamp(b)
    
    # Pass srgb=True to ensure the values are interpreted as sRGB
    return rio.Color.from_rgb(r, g, b, opacity, srgb=True)


def purple_shade(base_color: rio.Color, factor: float, purple_tint: float = 0.3) -> rio.Color:
    """
    Lightens/darkens a color while maintaining purple saturation.
    
    Instead of mixing with white (which desaturates), this blends with
    the primary purple color to keep the purple tone vibrant.
    """
    shaded = shade_color(base_color, factor)
    # Blend with primary color to maintain purple hue
    return shaded.blend(PRIMARY_COLOR, purple_tint)


# Dark theme - dark purple aesthetic
# Create neutral/hud colors that maintain purple saturation but stay VERY DARK
# Just barely lighter than background with subtle purple tint
_neutral_color = shade_color(BACKGROUND_COLOR_DARK, 1.02).blend(PRIMARY_COLOR, 0.15)
_hud_color = shade_color(BACKGROUND_COLOR_DARK, 1.03).blend(PRIMARY_COLOR, 0.2)

DARK_THEME = rio.Theme.from_colors(
    primary_color=PRIMARY_COLOR,
    secondary_color=SECONDARY_COLOR,
    background_color=BACKGROUND_COLOR_DARK,
    neutral_color=_neutral_color,  # Dark purple for cards
    hud_color=_hud_color,          # Slightly lighter for HUD/tooltips
    mode="dark",
)

# Light theme - light/white aesthetic  
LIGHT_THEME = rio.Theme.from_colors(
    primary_color=PRIMARY_COLOR,
    secondary_color=SECONDARY_COLOR,
    background_color=BACKGROUND_COLOR_LIGHT,
    neutral_color=shade_color(BACKGROUND_COLOR_LIGHT, 0.95),  # Slightly darker
    hud_color=shade_color(BACKGROUND_COLOR_LIGHT, 0.90),      # Even darker for HUD
    mode="light",
)
