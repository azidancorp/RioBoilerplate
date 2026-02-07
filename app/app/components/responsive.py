"""
Responsive utilities for mobile-friendly layouts.

This module provides breakpoint constants and helper functions
for building responsive UIs in Rio.

Responsive inheritance policy:
1. Any component that directly calls `is_mobile()` must inherit `ResponsiveComponent`
   so it rebuilds when crossing the mobile breakpoint.
2. Components that do not call `is_mobile()` directly may inherit `rio.Component`
   and rely on a responsive parent (for example, `CenterComponent`) for transitive
   refresh behavior.
"""

from __future__ import annotations

import typing as t

import rio

# Breakpoint constants (in Rio's font-height units).
MOBILE_BREAKPOINT = 40
TABLET_BREAKPOINT = 60

# Common layout constants.
MOBILE_CONTENT_WIDTH_PERCENT = 95

# Responsive layout tokens (mobile, desktop).
MOBILE_SPACING = 0.5
DESKTOP_SPACING = 1.0
MOBILE_MARGIN = 1
DESKTOP_MARGIN = 2
MOBILE_CHART_HEIGHT = 25
DESKTOP_CHART_HEIGHT = 30

# Content width presets for CenterComponent (width_percent values).
WIDTH_NARROW = 30       # Auth flows (login)
WIDTH_COMFORTABLE = 70  # Forms, content, modals (contact, settings, MFA, about, FAQ, pricing)
WIDTH_FULL = 90         # Data-heavy pages (dashboard, admin)


def is_mobile(session: rio.Session) -> bool:
    """Check if current window width is mobile-sized."""
    return session.window_width < MOBILE_BREAKPOINT


class ResponsiveComponent(rio.Component):
    """
    Base component that refreshes on window size change.

    Only triggers a rebuild when the mobile/desktop breakpoint is actually
    crossed, avoiding expensive rebuilds on every pixel of resize.
    """

    _was_mobile: t.ClassVar[bool] = False

    def _ensure_responsive_state(self) -> None:
        # Lazily initialize per-instance state without relying on dataclass hooks.
        if "_was_mobile" not in self.__dict__:
            self._was_mobile = is_mobile(self.session)

    @property
    def is_mobile(self) -> bool:
        """Whether the current window is mobile-sized."""
        return is_mobile(self.session)

    @property
    def flow_spacing(self) -> float:
        """Standard spacing for FlowContainer and similar layouts."""
        return MOBILE_SPACING if self.is_mobile else DESKTOP_SPACING

    @property
    def page_margin(self) -> float:
        """Standard page-level margin."""
        return MOBILE_MARGIN if self.is_mobile else DESKTOP_MARGIN

    @property
    def chart_height(self) -> float:
        """Standard chart min-height."""
        return MOBILE_CHART_HEIGHT if self.is_mobile else DESKTOP_CHART_HEIGHT

    @rio.event.on_window_size_change
    def on_window_size_change(self) -> None:
        self._ensure_responsive_state()
        new_mobile = is_mobile(self.session)
        if new_mobile != self._was_mobile:
            self._was_mobile = new_mobile
            self.force_refresh()
