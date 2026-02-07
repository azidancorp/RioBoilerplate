from __future__ import annotations

import rio
from fastapi import HTTPException

from app.scripts.message_utils import create_contact_submission
from app.validation import SecuritySanitizer
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE

@rio.page(
    name="ContactPage",
    url_segment="contact",
)
class ContactPage(ResponsiveComponent):
    """
    Contact page containing company contact information and a contact form.
    """

    name: str = ""
    email: str = ""
    message: str = ""
    error_message: str = ""
    banner_style: str = "danger"
    is_submitting: bool = False

    def on_submit_pressed(self):
        if self.is_submitting:
            return

        self.is_submitting = True

        try:
            sanitized_name = SecuritySanitizer.sanitize_string(self.name, 100)
            if not sanitized_name:
                self.error_message = "Please enter a valid name."
                self.banner_style = "danger"
                return

            if not self.email:
                self.error_message = "Please enter an email address."
                self.banner_style = "danger"
                return

            sanitized_email = SecuritySanitizer.validate_email_format(self.email)

            sanitized_message = SecuritySanitizer.sanitize_string(self.message, 10000)
            if not sanitized_message:
                self.error_message = "Please enter a valid message."
                self.banner_style = "danger"
                return

            response = create_contact_submission(
                name=sanitized_name,
                email=sanitized_email,
                message=sanitized_message,
            )

            self.banner_style = "success"
            submission_id = response.get("id")
            if submission_id is not None:
                self.error_message = (
                    "Your message has been sent successfully! "
                    f"Reference ID: {submission_id}."
                )
            else:
                self.error_message = "Your message has been sent successfully!"

            self.name = ""
            self.email = ""
            self.message = ""

        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, str) else "Unable to send your message."
            self.error_message = detail
            self.banner_style = "danger"
        except Exception:
            self.error_message = "Unexpected error. Please try again later."
            self.banner_style = "danger"
        finally:
            self.is_submitting = False

    def build(self) -> rio.Component:
        return CenterComponent(
            rio.Column(
                rio.Text(
                    "Contact Us",
                    style="heading1",
                    margin_bottom=2,
                    overflow="wrap",
                ),

                # Banner for messages
                rio.Banner(
                    text=self.error_message,
                    style=self.banner_style,
                    margin_bottom=1,
                ) if self.error_message else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

                # Contact Information Card
                rio.Row(
                    rio.Card(
                        rio.Column(
                            rio.Text(
                                "Get in Touch",
                                style="heading2",
                                margin_bottom=1,
                                overflow="wrap",
                            ),
                            rio.Text(
                                "We'd love to hear from you! Please fill out the form below or use our contact information.",
                                margin_bottom=2,
                                overflow="wrap",
                            ),

                            # Contact Form
                            rio.TextInput(
                                label="Name",
                                margin_bottom=1,
                                text=self.bind().name,
                                grow_x=True,
                            ),
                            rio.TextInput(
                                label="Email",
                                margin_bottom=1,
                                text=self.bind().email,
                                grow_x=True,
                            ),
                            rio.MultiLineTextInput(
                                label="Message",
                                text=self.bind().message,
                                min_height=6,
                                margin_bottom=2,
                                grow_x=True,
                            ),
                            rio.Button(
                                "Sending..." if self.is_submitting else "Send Message",
                                shape="rounded",
                                on_press=self.on_submit_pressed,
                                grow_x=True,
                            ),

                            # Company Information
                            rio.Text(
                                "Other Ways to Reach Us",
                                style="heading3",
                                margin_top=3,
                                margin_bottom=1,
                                overflow="wrap",
                            ),
                            rio.Text("Email: contact@buzzwordz.com", overflow="wrap"),
                            rio.Text("Phone: +1 (555) 123-4567", overflow="wrap"),
                            rio.Text("Address: 123 Innovation Drive, Silicon Valley, CA 94025", overflow="wrap"),

                            spacing=1,
                            margin=2,
                            grow_x=True,
                            min_width=0,
                        ),
                        grow_x=True,
                        min_width=0,
                    ),
                    grow_x=True,
                    min_width=0,
                ),
                grow_x=True,
                min_width=0,
            ),
            width_percent=WIDTH_COMFORTABLE,
        )
