
from __future__ import annotations

from dataclasses import KW_ONLY, field

import typing as t

import rio

from app.components.navbar import Navbar
from app.components.sidebar import Sidebar
from app.components.footer import Footer
from app.data_models import AppUser

class RootComponent(rio.Component):
    """
    This component will be used as the root for the app. This means that it will
    always be visible, regardless of which page is currently active.

    This makes it the perfect place to put components that should be visible on
    all pages, such as a navbar or a footer.

    Additionally, the root will contain a `rio.PageView`. Page views don't have
    any appearance of their own, but they are used to display the content of the
    currently active page. Thus, we'll always see the navbar and footer, with
    the content of the current page sandwiched in between.
    """

    def build(self) -> rio.Component:
        
        
        try:
            self.session[AppUser]
            user_is_logged_in = True
        except KeyError:
            user_is_logged_in = False
        
        
        return rio.Column(

            Navbar(),
            rio.Separator(),
            
            rio.Row(
                
                # only shown if logged in
                Sidebar(),
                
                rio.Column(
                    rio.PageView(
                        # Make sure the page view takes up all available space. Without
                        # this the sidebar would be assigned the same space as the page
                        # content.
                        grow_y=True,
                    ),     
                    align_y=0,
                    grow_x=True,
                ),
                align_y=0,
                grow_x=True,
                grow_y=True,
            ),

            Footer(),
        )
