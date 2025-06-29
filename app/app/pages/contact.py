from __future__ import annotations

from dataclasses import KW_ONLY, field
import typing as t
import re

import rio
from app.components.center_component import CenterComponent
from app.validation import SecuritySanitizer

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
        # Validate and sanitize inputs
        try:
            # Sanitize name
            sanitized_name = SecuritySanitizer.sanitize_string(self.name, 100)
            if not sanitized_name:
                self.error_message = "Please enter a valid name."
                self.banner_style = "danger"
                return

            # Validate email format
            if not self.email:
                self.error_message = "Please enter an email address."
                self.banner_style = "danger"
                return
            
            sanitized_email = SecuritySanitizer.validate_email_format(self.email)

            # Sanitize message
            sanitized_message = SecuritySanitizer.sanitize_string(self.message, 10000)
            if not sanitized_message:
                self.error_message = "Please enter a valid message."
                self.banner_style = "danger"
                return

            # Update form fields with sanitized values
            self.name = sanitized_name
            self.email = sanitized_email
            self.message = sanitized_message

            # If everything is correct, rejoice!
            self.banner_style = "success"
            self.error_message = "Your message has been sent successfully!"

        except Exception as e:
            self.error_message = "Invalid input. Please check your entries and try again."
            self.banner_style = "danger"

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
