from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field
from app.components.center_component import CenterComponent

import rio


@rio.page(
    name="Home",
    url_segment="",
)
class HomePage(rio.Component):
    """Home page of the application."""

    def build(self) -> rio.Component:
        """Build the home page UI."""

        return CenterComponent(
            component=rio.Column(
                rio.Text("Welcome to the Home Page!"),
                rio.Text(
                    "Your dashboard and content will appear here.",
                ),
            ),
            width_percent=50,
            height_percent=50,
        )