from __future__ import annotations

import rio
from app.components.center_component import CenterComponent
from app.components.responsive import WIDTH_COMFORTABLE


@rio.page(
    name="About",
    url_segment="about",
)
class AboutPage(rio.Component):
    """
    A sample page, which displays a humorous description of the company.
    """

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Column(
                rio.Markdown(
                    """
# About Us

Welcome to Buzzwordz Inc! Unleashing Synergistic Paradigms for Unprecedented Excellence since the day after yesterday.

## About Our Company

At Buzzwordz, we are all talk and no action. Our mission is to be the vanguards
of industry-leading solutions, leveraging bleeding-edge technologies to catapult
your business into the stratosphere of success. Our unparalleled team of ninjas,
gurus, and rockstars is dedicated to disrupting the status quo and actualizing
your wildest business dreams. We live, breathe, and eat operational excellence
and groundbreaking innovation.

## Synergistic Consulting

Unlock your business's quantum potential with our bespoke, game-changing
strategies. Our consulting services synergize cross-functional paradigms to
create a holistic ecosystem of perpetual growth and exponential ROI. Did I
mention paradigm-shifts? We've got those too.

## Agile Hyper-Development

We turn moonshot ideas into reality with our agile, ninja-level development
techniques. Our team of coding wizards crafts robust, scalable, and future-proof
solutions that redefine industry standards. 24/7 Proactive Hyper-Support
Experience next-gen support that anticipates your needs before you do. Our
omnipresent customer happiness engineers ensure seamless integration,
frictionless operation, and infinite satisfaction, day and night.
Embark on a journey of transformational growth and stratospheric success. Don't
delay, give us your money today.

Phone: (123) 456-7890

Email: info@yourwebsite.com

Address: 123 Fake Street, Moon
                    """,
                    margin_bottom=4,
                    align_y=0,
                    wrap=True,
                ),
                grow_x=True,
            ),
            width_percent=WIDTH_COMFORTABLE,
        )
