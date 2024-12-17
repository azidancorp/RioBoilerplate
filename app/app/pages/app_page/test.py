from __future__ import annotations
from dataclasses import KW_ONLY, field
import typing as t
import rio
import random

@rio.page(
    name="Test",
    url_segment="test",
)

class ProgressButton(rio.Component):
    bgc: rio.Color = rio.Color.from_hex("#000000")
    clicks: int = 0

    def _on_button_press(self) -> None:
        self.clicks += 1
        if self.clicks >= 10:
            self.clicks = 0
            self._change_color()

    def _change_color(self) -> None:
        random_color = "#{:06x}".format(random.randint(0, 0xFFFFFF))
        self.bgc = rio.Color.from_hex(random_color)

    def build(self) -> rio.Component:
        return rio.Button(
            rio.Column(
                rio.Text("Click repeatedly to fill up the progress bar",
                         style=rio.TextStyle(
                             fill=self.bgc,
                         )),
                rio.ProgressBar(self.clicks / 10, min_width=15, min_height=1),
                spacing=0.5,
                margin=0.5,
            ),
            on_press=self._on_button_press,
            align_x=0.5,
            align_y=0.5,
        )