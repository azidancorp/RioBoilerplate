from __future__ import annotations

import rio
from app.navigation import get_public_mobile_drawer_links


class PublicNav(rio.Component):
    """
    Simple navigation used in the mobile drawer when the user is logged out.
    """

    BUTTON_WIDTH: float = 9

    def build(self) -> rio.Component:
        links: list[rio.Component] = []

        for title, url in get_public_mobile_drawer_links():
            links.append(
                rio.Link(
                    rio.Button(
                        title,
                        shape="rounded",
                        min_width=self.BUTTON_WIDTH,
                    ),
                    url,
                    align_x=0,
                )
            )

        return rio.Column(
            *links,
            spacing=0.8,
            margin=1,
            align_x=0,
            align_y=0,
            grow_y=True,
        )
