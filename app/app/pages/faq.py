from __future__ import annotations

import rio
from app.components.center_component import CenterComponent

@rio.page(
    name="FAQ",
    url_segment="faq",
)
class FAQPage(rio.Component):
    """
    Frequently Asked Questions page with whimsical answers about our SaaS product.
    """
    
    def build(self) -> rio.Component:
        """Build the FAQ page with expandable questions and answers."""
        return CenterComponent(
            rio.Column(
                rio.Text("Frequently Asked Questions", style="heading1", margin_bottom=2),
                
                rio.Revealer(
                    header="What exactly is this 'Sidekick Plan' and will it actually give me superpowers?",
                    header_style="heading3",
                    content=rio.Text(
                        "While our Sidekick Plan won't give you the ability to fly or become invisible "
                        "(we're still working on that feature), it will give you super-productivity powers! "
                        "Think of it as having a digital butler who's really good at organizing things, "
                        "but occasionally gets confused about whether a tomato is a fruit or vegetable.",
                        overflow="wrap"
                    ),
                ),
                
                rio.Revealer(
                    header="Is the 'Hero Plan' named after someone specific?",
                    header_style="heading3",
                    content=rio.Text(
                        "The Hero Plan is actually named after our first customer's pet hamster, Hero, "
                        "who apparently had a knack for data analytics. We can neither confirm nor deny "
                        "that the hamster is now our Chief Innovation Officer.",
                        overflow="wrap"
                    ),
                ),
                
                rio.Revealer(
                    header="Why does yearly billing come with a 'Time Travel Discount'?",
                    header_style="heading3",
                    content=rio.Text(
                        "We believe signing up for a year harnesses the power of synergy across spacetime. Essentially, "
                        "you're investing in a future brimming with triumphant high-fives and unwavering trust in our "
                        "innovation ninjas. Paying annually also whispers sweet nothings to your bottom line by offering "
                        "two months of potential disruptions on the house.",
                        overflow="wrap"
                    ),
                ),
                
                rio.Revealer(
                    header="Do you really provide '24/7 Support' or is that just when your coffee machine is working?",
                    header_style="heading3",
                    content=rio.Text(
                        "Our support team is indeed available 24/7, powered by a mysterious combination of "
                        "coffee, enthusiasm, and the occasional pizza. We've also trained a group of nocturnal "
                        "coding ninjas for those 3 AM 'why isn't my code working' emergencies. "
                        "Our dedicated support ninjas don't sleep—they merely enter a hyper-focused meditative flow state. ",
                        overflow="wrap"
                    ),
                ),
                
                rio.Revealer(
                    header="What's the difference between 'Basic Analytics' and 'Advanced Analytics'?",
                    header_style="heading3",
                    content=rio.Text(
                        "Basic Analytics tells you what happened. Advanced Analytics tells you what happened, "
                        "why it happened, and occasionally predicts what might happen next (though we're still "
                        "working on predicting lottery numbers). It's like upgrading from a crystal ball to a "
                        "quantum supercomputer, but with more colorful graphs.",
                        overflow="wrap"
                    ),
                ),
                
                rio.Revealer(
                    header="Can I pay with cryptocurrency?",
                    header_style="heading3",
                    content=rio.Text(
                        "We currently accept all major credit cards and traditional payment methods. "
                        "We tried accepting cryptocurrency, but our payment processor got too excited "
                        "about blockchain and tried to turn our entire codebase into an NFT.",
                        overflow="wrap"
                    ),
                ),
                
                spacing=2,
            ),
            # max_width=800,
            width_percent=80,
        )
