from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
import rio


class CenterComponent(rio.Component):
    component: rio.Component
    width_percent: int = 100
    height_percent: int = 100
    # x_proportions: List[int]
    # y_proportions: List[int]
    
    def __post_init__(self):
        self.grow_x = True
        self.grow_y = True
    
    def wrap_horizontally(self, component: rio.Component):
        
        return rio.Row(
            rio.Spacer(),
            component,
            rio.Spacer(),
            proportions=self.x_proportions,
            grow_x=True,
        )
    
    def wrap_vertically(self, component: rio.Component):
        
        return rio.Column(
            rio.Spacer(),
            component,
            rio.Spacer(),
            proportions=self.y_proportions,
            grow_y=True,
        )
    
    def build(self) -> rio.Component:
        self.x_proportions: t.List[int] = [round((100-self.width_percent)/2), self.width_percent, round((100-self.width_percent)/2)]
        self.y_proportions: t.List[int] = [round((100-self.height_percent)/2), self.height_percent, round((100-self.height_percent)/2)]

        
        if self.width_percent == 100 and self.height_percent == 100:
            return self.component
        elif self.width_percent != 100 and self.height_percent == 100:
            return self.wrap_horizontally(self.component)
        elif self.width_percent == 100 and self.height_percent != 100:
            return self.wrap_vertically(self.component)
        else:
            return self.wrap_vertically(self.wrap_horizontally(self.component))