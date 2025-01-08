from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t

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

    def on_submit_pressed(self):
        print("Contact form submitted")
        print("Name:", self.name)
        print("Email:", self.email)
        print("Message:", self.message)

    def build(self) -> rio.Component:
        return rio.Column(
            rio.Text(
                "Contact Us",
                style="heading1",
                margin_bottom=2,
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
