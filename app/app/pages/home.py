from __future__ import annotations

import typing as t
from dataclasses import KW_ONLY, field

from app.components.center_component import CenterComponent
from app.components.testimonial import Testimonial
from app.scripts.utils import load_from_html
from app.pages.pricing import PricingPlans
from app.pages.faq import FAQSection

import rio


class HeroSection(rio.Component):
    """Hero Section with headline, sub-headline, visual elements, and CTA."""

    def build(self) -> rio.Component:
        return rio.Column(
            # Strong headline using proven formulas
            
            rio.Row(
                rio.Column(
                    
                    rio.Column(
                        rio.Text(
                            "Achieve <Desired Outcome>",
                            style=rio.TextStyle(
                                font_weight='bold',
                                fill=rio.Color.from_hex("#FFFFFF")),
                        ),
                        rio.Text(
                            "without <Pain Point>",
                            style=rio.TextStyle(
                                font_weight='bold',
                                fill=rio.Color.from_hex("#FFFFFF")),
                        ),
                    ),
                    
                    # Sub-headline bridging to CTA
                    rio.Text(
                        "Say goodbye to outdated methods and hello to success with our all-in-one platform.",
                        overflow='wrap',
                        style=rio.TextStyle(
                            fill=rio.Color.from_hex("#CCCCCC")),
                    ),
                    # Clear CTA
                    rio.Button(
                        "Call To Action!",
                        on_press=lambda: print("Primary CTA clicked!"),
                        shape='rounded',
                        align_x=0,
                        align_y=0.5,
                    ),
                ),      

                rio.Column(
                    rio.Image(
                        image=rio.URL("https://dummyimage.com/400x400/000/fff.png&text=Hero+Image"),
                        min_width=30,
                        min_height=30,
                    ),
                    
                ),
            ),
            spacing=2,
            align_y=0.5,
        )


class OldWaySection(rio.Component):
    """Old Way Section highlighting pain points and challenges in a two-column layout."""

    def build(self) -> rio.Component:
        return rio.Column(
            rio.Row(
                
                # Left column for image
                rio.Column(
                    rio.Image(
                        image=rio.URL("https://dummyimage.com/400x400/aaa/fff&text=Old+Way"),
                        min_width=20,
                        min_height=20,
                    ),
                ),
                
                # Right column for text
                rio.Column(
                    rio.Text(
                        "The Old Way: Painful, Expensive, and Time-Consuming",
                        style='heading1',
                    ),
                    rio.Text(
                        "Are you tired of juggling multiple platforms, facing never-ending deadlines, "
                        "and overpaying for mediocre results?",
                    ),
                    rio.Text(
                        "Most solutions fail to address the root problems, causing more chaos "
                        "and confusion than ever before.",
                    ),
                    align_y=0,
                    spacing=1,
                ),

            ),
            spacing=1,
        )


class NewWaySection(rio.Component):
    """New Way Section presenting solution features, benefits, and outcomes in a two-column layout."""

    def build(self) -> rio.Component:
        return rio.Column(
            rio.Row(
                # Left column for text
                rio.Column(
                    rio.Text(
                        "The New Way: A Seamless, All-in-One Transformation",
                        style='heading1',
                    ),
                    rio.Text(
                        "Our platform streamlines every process, so you can focus on delivering greatness "
                        "to your customers.",
                    ),
                    rio.Text(
                        "Save time, reduce costs, and watch your business thrive with minimal effort.",
                    ),
                    rio.Text(
                        "Worried about the learning curve? Fear not—our 24/7 support and step-by-step guides "
                        "have you covered.",
                        style=rio.TextStyle(italic=True),
                    ),
                    align_y=0,
                    spacing=1,
                ),
                # Right column for image
                rio.Column(
                    rio.Image(
                        image=rio.URL("https://dummyimage.com/400x400/000/fff&text=New+Way"),
                        min_width=20,
                        min_height=20,
                    ),
                ),
            ),
            spacing=1,
        )


class SocialProofSection(rio.Component):
    """Social Proof Section with testimonials, case studies, and FAQs."""

    def build(self) -> rio.Component:
        return rio.Column(
            rio.Text(
                "Real Results from Real Customers",
                style='heading1'
            ),
            
            rio.FlowContainer(
                Testimonial(
                    quote="This platform has truly changed the way we do business. Absolutely remarkable!",
                    name="Jane Doe",
                    company="Acme Inc.",
                ),
                Testimonial(
                    quote="We doubled our revenue in just three months, all thanks to this platform.",
                    name="John Smith",
                    company="Tech Solutions",
                ),
                Testimonial(
                    quote="The customer support is unparalleled. They're always there when we need them.",
                    name="Alice Johnson",
                    company="Global Innovations",
                ),
                Testimonial(
                    quote="This solution has streamlined our operations beyond our wildest expectations.",
                    name="Bob Williams",
                    company="Startup Dynamo",
                ),

                row_spacing=1,
                column_spacing=1,
                justify="center",
            ),
            # Case Studies
            rio.Column(
                rio.Text(
                    "Success Stories That Drive Results",
                    style='heading1',
                    margin_bottom=1,
                ),
                rio.FlowContainer(
                    rio.Column(
                        rio.Text(
                            "Global Tech Solutions",
                            style='heading2',
                        ),
                        rio.Text("Industry: Enterprise Software"),
                        rio.Text(
                            "• 50% reduction in operational costs\n"
                            "• 3x faster project delivery\n"
                            "• 98% customer satisfaction rate",
                        ),
                        spacing=0.5,
                    ),
                    rio.Column(
                        rio.Text(
                            "StartUp Innovators",
                            style='heading2',
                        ),
                        rio.Text("Industry: E-commerce"),
                        rio.Text(
                            "• Scaled to $2M ARR in 18 months\n"
                            "• 75% reduction in customer churn\n"
                            "• 4x increase in team productivity",
                        ),
                        spacing=0.5,
                    ),
                    rio.Column(
                        rio.Text(
                            "DataDriven Analytics",
                            style='heading2',
                        ),
                        rio.Text("Industry: Business Intelligence"),
                        rio.Text(
                            "• 200% ROI within first year\n"
                            "• 40% increase in data accuracy\n"
                            "• 5x faster reporting cycles",
                        ),
                        spacing=0.5,
                    ),
                    row_spacing=2,
                    column_spacing=2,
                    justify="center",
                ),
                spacing=1,
            ),
            # FAQ
            FAQSection(),

            spacing=2,
        )


class CallToActionSection(rio.Component):
    """Final Call to Action with primary and secondary options, plus exit-intent popups."""

    def build(self) -> rio.Component:
        return rio.Column(
            # Primary CTA
            rio.Button(
                "Start Your Free Trial",
                on_press=lambda: print("Primary CTA clicked!"),
                shape='rounded',
            ),
            # Secondary CTA
            rio.Button(
                "Learn More",
                on_press=lambda: print("Secondary CTA clicked!"),
                shape='rounded',
            ),
            # Exit-intent popup placeholder
            rio.Text(
                "(Exit-Intent Popup would appear when user attempts to leave)",
                style=rio.TextStyle(italic=True),
            ),


            PricingPlans(),
            
            spacing=2,
        )


class ExampleJSPage(rio.Component):
    def build(self) -> rio.Component:
        return rio.Column(
            rio.Text("Example JS Page"),
            rio.Webview(
                content=load_from_html("JSPages/test.html"),
                min_width=0,
                grow_x=True,
            ),
            grow_x=True,
            spacing=2,
        )


@rio.page(
    name="Home",
    url_segment="",
)
class HomePage(rio.Component):
    """Home page of the application with five distinct sections."""

    def build(self) -> rio.Component:
        """Build the home page UI with a master column containing all sections."""
        return CenterComponent(
            rio.Column(
                HeroSection(),
                OldWaySection(),
                NewWaySection(),
                SocialProofSection(),
                CallToActionSection(),
                ExampleJSPage(),
                spacing=8,
            ),
            # width_percent=80,
        )
