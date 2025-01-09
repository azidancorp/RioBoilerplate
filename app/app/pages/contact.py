from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
import re

import rio
from app.components.center_component import CenterComponent

@rio.page(
    name="ContactPage",
    url_segment="contact",
)
class ContactPage(rio.Component):
    """
    Contact page containing company contact information and a contact form.
    """

    name: str = ""
    email: str = ""
    message: str = ""
    error_message: str = ""
    banner_style: str = "danger"

    def on_submit_pressed(self):
        # Validate the name, email, and message
        if not self.name or not self.email or not self.message:
            self.error_message = "Please fill in all fields."
            self.banner_style = "danger"
            return

        # Validate the email format
        pattern = r"[^@]+@[^@]+\.[^@]+"
        if not re.match(pattern, self.email):
            self.error_message = "Invalid email format."
            self.banner_style = "danger"
            return

        # If everything is correct, rejoice!
        self.banner_style = "success"
        self.error_message = "Your message has been sent successfully!"

    def build(self) -> rio.Component:
        return rio.Column(
            rio.Text(
                "Contact Us",
                style="heading1",
                margin_bottom=2,
            ),

            # Banner for messages
            rio.Banner(
                text=self.error_message,
                style=self.banner_style,
                margin_bottom=1,
            ),

            # Contact Information Card
            rio.Card(
                rio.Column(
                    rio.Text(
                        "Get in Touch",
                        style="heading2",
                        margin_bottom=1,
                    ),
                    rio.Text(
                        "We'd love to hear from you! Please fill out the form below or use our contact information.",
                        margin_bottom=2,
                    ),

                    # Contact Form
                    rio.TextInput(
                        label="Name",
                        margin_bottom=1,
                        text=self.bind().name,
                    ),
                    rio.TextInput(
                        label="Email",
                        margin_bottom=1,
                        text=self.bind().email,
                    ),
                    rio.MultiLineTextInput(
                        label="Message",
                        text=self.bind().message,
                        min_height=6,
                        margin_bottom=2,
                    ),
                    rio.Button(
                        "Send Message",
                        shape="rounded",
                        on_press=self.on_submit_pressed,
                    ),

                    # Company Information
                    rio.Text(
                        "Other Ways to Reach Us",
                        style="heading3",
                        margin_top=3,
                        margin_bottom=1,
                    ),
                    rio.Text("Email: contact@buzzwordz.com"),
                    rio.Text("Phone: +1 (555) 123-4567"),
                    rio.Text("Address: 123 Innovation Drive, Silicon Valley, CA 94025"),

                    spacing=1,
                    margin=2,
                ),
            ),
            align_x=0.5,
            min_width=60,
        )
