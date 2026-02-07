from __future__ import annotations

import rio
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE


class FAQSection(ResponsiveComponent):
    """
    Section for frequently asked questions with expandable answers.
    """
    
    def build(self) -> rio.Component:
        """Build the FAQ page with expandable questions and answers."""
        mobile = self.is_mobile
        title_style = "heading2" if mobile else "heading1"  # Rio text styles

        items = [
            FAQItem(
                question="What exactly is this 'Sidekick Plan' and will it actually give me superpowers?",
                answer=(
                    "While our Sidekick Plan won't give you the ability to fly or become invisible "
                    "(we're still working on that feature), it will give you super-productivity powers! "
                    "Think of it as having a digital butler who's really good at organizing things, "
                    "but occasionally gets confused about whether a tomato is a fruit or vegetable."
                ),
            ),
            FAQItem(
                question="Is the 'Hero Plan' named after someone specific?",
                answer=(
                    "The Hero Plan is actually named after our first customer's pet hamster, Hero, "
                    "who apparently had a knack for data analytics. We can neither confirm nor deny "
                    "that the hamster is now our Chief Innovation Officer."
                ),
            ),
            FAQItem(
                question="Why does yearly billing come with a 'Time Travel Discount'?",
                answer=(
                    "We believe signing up for a year harnesses the power of synergy across spacetime. Essentially, "
                    "you're investing in a future brimming with triumphant high-fives and unwavering trust in our "
                    "innovation ninjas. Paying annually also whispers sweet nothings to your bottom line by offering "
                    "two months of potential disruptions on the house."
                ),
            ),
            FAQItem(
                question="Do you really provide '24/7 Support' or is that just when your coffee machine is working?",
                answer=(
                    "Our support team is indeed available 24/7, powered by a mysterious combination of "
                    "coffee, enthusiasm, and the occasional pizza. We've also trained a group of nocturnal "
                    "coding ninjas for those 3 AM 'why isn't my code working' emergencies. "
                    "Our dedicated support ninjas don't sleep—they merely enter a hyper-focused meditative flow state."
                ),
            ),
            FAQItem(
                question="What's the difference between 'Basic Analytics' and 'Advanced Analytics'?",
                answer=(
                    "Basic Analytics tells you what happened. Advanced Analytics tells you what happened, "
                    "why it happened, and occasionally predicts what might happen next (though we're still "
                    "working on predicting lottery numbers). It's like upgrading from a crystal ball to a "
                    "quantum supercomputer, but with more colorful graphs."
                ),
            ),
            FAQItem(
                question="Can I pay with cryptocurrency?",
                answer=(
                    "We currently accept all major credit cards and traditional payment methods. "
                    "We tried accepting cryptocurrency, but our payment processor got too excited "
                    "about blockchain and tried to turn our entire codebase into an NFT."
                ),
            ),
        ]

        return rio.Column(
            rio.Text(
                "Frequently Asked Questions",
                style=title_style,
                margin_bottom=2,
                overflow="wrap",
                grow_x=True,
            ),
            *items,

            spacing=2,
            grow_x=True,
        )


class FAQItem(rio.Component):
    """Single FAQ row with a wrap-safe header and collapsible answer."""

    question: str
    answer: str
    is_open: bool = False

    def _toggle(self) -> None:
        self.is_open = not self.is_open

    def build(self) -> rio.Component:
        return rio.Card(
            rio.Column(
                rio.Row(
                    rio.Text(
                        self.question,
                        overflow="wrap",
                        style="text",
                        grow_x=True,
                    ),
                    rio.IconButton(
                        icon="material/expand-less" if self.is_open else "material/expand-more",
                        on_press=self._toggle,
                    ),
                    spacing=0.4,
                    grow_x=True,
                    align_y=0.5,
                ),
                rio.Text(
                    self.answer,
                    overflow="wrap",
                    margin_top=0.5,
                ) if self.is_open else rio.Spacer(min_height=0, min_width=0, grow_x=False, grow_y=False),
                spacing=0.5,
                margin=1,
                grow_x=True,
            ),
            grow_x=True,
            min_width=0,
        )



@rio.page(
    name="FAQ",
    url_segment="faq",
)
class FAQPage(rio.Component):
    """
    Frequently Asked Questions page with whimsical answers about our SaaS product.
    """

    def build(self) -> rio.Component:

        return CenterComponent(
            FAQSection(),
            width_percent=WIDTH_COMFORTABLE,
        )
