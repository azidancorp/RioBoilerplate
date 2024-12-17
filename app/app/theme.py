from re import T
import rio

PRIMARY_COLOR = rio.Color.from_hsv(0.75, 0.5, 1)
SECONDARY_COLOR = rio.Color.from_hsv(0.75, 1, 1)
BACKGROUND_COLOR = rio.Color.from_hsv(0.75, 0.9, 0.15)

# PRIMARY_COLOR = rio.Color.from_hsv(0.75, 0, 1)
# SECONDARY_COLOR = rio.Color.from_hsv(0.75, 0, 1)
# BACKGROUND_COLOR = rio.Color.from_hsv(0.75, 0, 0.15)

# Let’s create a helper function to shade colors.
# factor < 1 will darken the color, factor > 1 will lighten it.
def shade_color(base_color: rio.Color, factor: float) -> rio.Color:
    """
    Shades the given color by the specified factor.
    
    - factor < 1: Darkens the color by mixing it with black.
    - factor > 1: Lightens the color by mixing it with white.
    """
    def clamp(v: float) -> float:
        """Ensures the value stays within the 0.0 to 1.0 range."""
        return max(0.0, min(1.0, v))
    
    # Access the color components correctly
    r, g, b = base_color.red, base_color.green, base_color.blue
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
    
    return rio.Color.from_rgb(r, g, b, opacity)



# Construct the Rio theme using our chosen colors. 
# We trust Rio to apply them consistently throughout our app.
THEME = rio.Theme.from_colors(
    primary_color=PRIMARY_COLOR,
    secondary_color=SECONDARY_COLOR,
    background_color=BACKGROUND_COLOR,
    neutral_color=shade_color(BACKGROUND_COLOR, 1.05),
    hud_color=shade_color(BACKGROUND_COLOR, 1.1),
    
    # text_color=SECONDARY_COLOR,
    mode="dark",
)
