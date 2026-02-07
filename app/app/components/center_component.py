from __future__ import annotations

import typing as t
import rio

from app.components.responsive import ResponsiveComponent, MOBILE_CONTENT_WIDTH_PERCENT


class CenterComponent(ResponsiveComponent):
    """
    A component that centers its child with configurable width/height percentages.

    Supports responsive widths - use mobile_width_percent for different mobile sizing.
    This component can provide transitive responsive refresh for children that
    don't directly call `is_mobile()`.
    """
    component: rio.Component
    width_percent: int = 100
    height_percent: int = 100
    mobile_width_percent: int = MOBILE_CONTENT_WIDTH_PERCENT  # Default 95% on mobile

    def __post_init__(self) -> None:
        self.grow_x = True
        self.grow_y = True

    def _sanitize_percent(self, value: int) -> int:
        return max(0, min(100, int(value)))

    def _get_x_proportions(self, width: int) -> t.List[int]:
        """Calculate horizontal proportions for centering."""
        width = self._sanitize_percent(width)
        side = round((100 - width) / 2)
        return [side, width, side]

    def _get_y_proportions(self, height: int) -> t.List[int]:
        """Calculate vertical proportions for centering."""
        height = self._sanitize_percent(height)
        side = round((100 - height) / 2)
        return [side, height, side]

    def _wrap_horizontally(self, component: rio.Component, width: int) -> rio.Component:
        return rio.Row(
            rio.Spacer(),
            component,
            rio.Spacer(),
            proportions=self._get_x_proportions(width),
            grow_x=True,
        )

    def _wrap_vertically(self, component: rio.Component, height: int) -> rio.Component:
        return rio.Column(
            rio.Spacer(),
            component,
            rio.Spacer(),
            proportions=self._get_y_proportions(height),
            grow_y=True,
        )

    def build(self) -> rio.Component:
        # Determine effective width based on screen size
        if self.mobile_width_percent is not None and self.is_mobile:
            effective_width = self._sanitize_percent(self.mobile_width_percent)
        else:
            effective_width = self._sanitize_percent(self.width_percent)

        effective_height = self._sanitize_percent(self.height_percent)

        if effective_width == 100 and effective_height == 100:
            return self.component
        elif effective_width != 100 and effective_height == 100:
            return self._wrap_horizontally(self.component, effective_width)
        elif effective_width == 100 and effective_height != 100:
            return self._wrap_vertically(self.component, effective_height)
        else:
            return self._wrap_vertically(
                self._wrap_horizontally(self.component, effective_width),
                effective_height,
            )
