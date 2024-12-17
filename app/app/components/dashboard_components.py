from __future__ import annotations

from dataclasses import KW_ONLY, field
from typing import *  # type: ignore

import rio



class DeltaCard(rio.Component):
    title: str
    value: str
    color: rio.Color = rio.Color.from_hex('#808080')
    delta_a: float = 0
    delta_b: float = 0

    def build(self) -> rio.Component:
        # Determine colors based on delta_a
        if self.delta_a > 0:
            delta_a_color = rio.Color.from_hex('#2ECC71')  # Green
        elif self.delta_a < 0:
            delta_a_color = rio.Color.from_hex('#E74C3C')  # Red
        else:
            delta_a_color = rio.Color.from_hex('#7F8C8D')  # Gray

        # Determine colors based on delta_b
        if self.delta_b > 0:
            delta_b_color = rio.Color.from_hex('#2ECC71')  # Green
        elif self.delta_b < 0:
            delta_b_color = rio.Color.from_hex('#E74C3C')  # Red
        else:
            delta_b_color = rio.Color.from_hex('#7F8C8D')  # Gray

        return rio.Card(
            content=rio.Column(
                # Title Text
                rio.Text(
                    self.title,
                    overflow='wrap',
                ),
                
                # Value Text
                rio.Text(
                    self.value,
                    style=rio.TextStyle(
                        font_size=2,
                    ),
                ),
                
                # Delta Values Row
                rio.Row(
                    # Delta A Column
                    rio.Column(
                        rio.Text(
                            "Delta A",
                            style=rio.TextStyle(
                                fill=rio.Color.from_hex('#7F8C8D'),
                            ),
                            align_x=0,
                        ),
                        rio.Text(
                            f"{'+' if self.delta_a >= 0 else ''}{self.delta_a}",
                            style=rio.TextStyle(
                                fill=delta_a_color,
                            ),
                        ),
                        align_y=0,
                    ),
                    
                    # Spacer to push Delta B to the right
                    rio.Spacer(),
                    
                    # Delta B Column
                    rio.Column(
                        rio.Text(
                            "Delta B",
                            style=rio.TextStyle(
                                fill=rio.Color.from_hex('#7F8C8D'),
                            ),
                            align_x=1,
                        ),
                        rio.Text(
                            f"{'+' if self.delta_b >= 0 else ''}{self.delta_b}",
                            style=rio.TextStyle(
                                fill=delta_b_color,
                            ),
                        ),
                        align_y=0,
                    ),
                    
                    # align_x='stretch',
                    grow_x=True,
                ),
                
                spacing=0.5,
                margin=1,
            ),
            
            color=self.color,
            elevate_on_hover=True,
            corner_radius=0.2,
        )
