from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
import rio


# ● The issue with center_component.py is a variable scoping problem:

#   Problem:

#   The wrap_horizontally() and wrap_vertically() methods (lines 25 and 35) reference self.x_proportions and self.y_proportions, but     
#   these attributes are only created in the build() method (lines 40-41).

#   Issue Details:

#   def wrap_horizontally(self, component: rio.Component):
#       return rio.Row(
#           rio.Spacer(),
#           component,
#           rio.Spacer(),
#           proportions=self.x_proportions,  # ❌ AttributeError: 'CenterComponent' object has no attribute 'x_proportions'
#           grow_x=True,
#       )

#   The variables self.x_proportions and self.y_proportions don't exist when wrap_horizontally() or wrap_vertically() are called,        
#   since they're only defined inside the build() method.

#   Why This Causes Runtime Errors:

#   1. If wrap_horizontally() or wrap_vertically() are called before build(), it will raise an AttributeError
#   2. Even if called after build(), it's poor design since the methods depend on internal state created elsewhere

#   The Fix:

#   The proportions calculation should be moved to the methods themselves or made into proper instance attributes. The methods should    
#    compute the proportions they need rather than depending on externally set attributes.

#   This is definitely a bug that would cause runtime failures if these wrapper methods are called independently.

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