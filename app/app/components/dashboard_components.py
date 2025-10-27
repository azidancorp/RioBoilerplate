from __future__ import annotations

from dataclasses import KW_ONLY, field
from typing import Optional

import rio



class DeltaCard(rio.Component):
    title: str
    value: str
    color: rio.Color = rio.Color.from_hex('#808080')
    delta_a_title: str = ""
    delta_b_title: str = ""
    delta_a: Optional[float] = None
    delta_b: Optional[float] = None

    def build(self) -> rio.Component:
        def get_delta_color(delta: Optional[float]) -> rio.Color:
            if delta is None or delta == 0:
                return rio.Color.from_hex('#7F8C8D')  # Gray
            return rio.Color.from_hex('#2ECC71') if delta > 0 else rio.Color.from_hex('#E74C3C')

        def format_delta(delta: Optional[float]) -> str:
            if delta is None:
                return ""
            sign = '+' if delta > 0 else ''
            return f"{sign}{delta:.0f}" if delta.is_integer() else f"{sign}{delta:.2f}"

        delta_a_color = get_delta_color(self.delta_a)
        delta_b_color = get_delta_color(self.delta_b)

        content = [
            rio.Text(self.title, overflow='wrap'),
            rio.Text(self.value, style=rio.TextStyle(font_size=2))
        ]

        if self.delta_a is not None or self.delta_b is not None:
            delta_row = rio.Row(
                rio.Column(
                    rio.Text(
                        self.delta_a_title,
                        align_x=0,
                        overflow='wrap'
                    ),
                    rio.Text(
                        format_delta(self.delta_a),
                        style=rio.TextStyle(fill=delta_a_color),
                        overflow='wrap'
                    ),
                    align_y=0
                ) if self.delta_a is not None else rio.Spacer(),
                rio.Spacer(),
                rio.Column(
                    rio.Text(
                        self.delta_b_title,
                        align_x=1,
                        overflow='wrap'
                    ),
                    rio.Text(
                        format_delta(self.delta_b),
                        style=rio.TextStyle(fill=delta_b_color),
                        overflow='wrap'
                    ),
                    align_y=0
                ) if self.delta_b is not None else rio.Spacer(),
                grow_x=True
            )
            content.append(delta_row)

        return rio.Card(
            content=rio.Column(*content, spacing=0.5, margin=1),
            color=self.color,
            elevate_on_hover=True,
            corner_radius=0.2
        )
