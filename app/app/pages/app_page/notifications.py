from __future__ import annotations

from dataclasses import field
from datetime import datetime, timedelta

import rio

from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_COMFORTABLE
from app.persistence import Persistence
from app.data_models import UserSession
from app.currency import get_currency_config


def get_sample_notifications() -> list[dict[str, str | int]]:
    currency_plural = get_currency_config().name_plural
    return [
        {
            "type": "SUCCESS",
            "message": "Welcome to your brand new Supernova Plan! Now with added synergy and paradigm-shifting capabilities.",
            "minutes_ago": 5,
        },
        {
            "type": "INFO",
            "message": "Great news! Our nocturnal coding ninjas deployed a new feature overnight. Dive in and disrupt the status quo!",
            "hours_ago": 2,
        },
        {
            "type": "WARNING",
            "message": f"Your {currency_plural} are running low! Reach out to your account rep or consider leveling up to the Infinity Plan.",
            "days_ago": 1,
        },
        {
            "type": "ERROR",
            "message": "Oops! We encountered a glitch in the matrix while trying to harness the power of quantum synergy. Our temporal engineers are on it!",
            "days_ago": 2,
        },
    ]


# Notification color definitions
NOTIFICATION_COLORS = {
    "SUCCESS": rio.Color.from_hex("#4CAF50"),  # Green
    "INFO": rio.Color.from_hex("#2196F3"),     # Blue
    "WARNING": rio.Color.from_hex("#FF9800"),   # Orange
    "ERROR": rio.Color.from_hex("#F44336"),     # Red
}


class Notification(rio.Component):
    """
    Represents a single notification entry as a Rio component.
    Stores the notification type, message content, and timestamp for display.
    """

    # Define the fields that will store data in this component
    type: str
    message: str
    timestamp: datetime

    def get_card_color(self) -> rio.Color:
        """
        Maps the notification type to a Rio Color.
        """
        return NOTIFICATION_COLORS.get(self.type, rio.Color.from_hex("#424242"))  # Default dark grey

    def build(self) -> rio.Component:
        """
        Returns a Card that visually represents the notification.
        """
        return rio.Card(
            rio.Column(
                rio.Text(
                    f"{self.type} Notification",
                    style="heading3",
                    overflow="wrap",
                ),
                rio.Text(
                    self.message,
                    overflow="wrap",
                ),
                rio.Text(
                    f"Timestamp: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                    overflow="wrap",
                ),
                spacing=0.5,
                margin=0.75,
            ),
            color=self.get_card_color(),
        )


@rio.page(
    name="Notifications",
    url_segment="notifications",
)
class NotificationsPage(ResponsiveComponent):
    """
    A page listing the user's notifications, with the ability to mark
    them as read or clear them entirely.
    """

    notification_data: list[dict] = field(default_factory=list)
    error_message: str = ""

    @rio.event.on_populate
    async def on_populate(self):
        """
        Fetch notifications from the database for the logged-in user
        and populate the notifications list with some sample data.
        """
        try:
            user_session = self.session[UserSession]
            persistence = self.session[Persistence]
            now = datetime.now()

            # Example: Replace with your actual model/method for fetching notifications:
            #   db_notifications = await persistence.get_notifications_for_user(user_session.user_id)
            
            # For demonstration, we'll load the sample notifications:
            self.notification_data = []
            for notif in get_sample_notifications():
                timestamp = now
                if "minutes_ago" in notif:
                    timestamp -= timedelta(minutes=notif["minutes_ago"])
                elif "hours_ago" in notif:
                    timestamp -= timedelta(hours=notif["hours_ago"])
                elif "days_ago" in notif:
                    timestamp -= timedelta(days=notif["days_ago"])
                
                self.notification_data.append({
                    "type": notif["type"],
                    "message": notif["message"],
                    "timestamp": timestamp
                })

        except Exception as e:
            self.error_message = f"Failed to load notifications: {str(e)}"

    async def on_mark_all_as_read_pressed(self, _=None):
        """
        Marks all notifications as read (if you track read/unread state),
        then refreshes the list. Adjust to match your actual logic.
        """
        try:
            user_session = self.session[UserSession]
            persistence = self.session[Persistence]

            # Placeholder for marking notifications as read in the DB.
            # e.g., await persistence.mark_all_notifications_as_read(user_session.user_id)

            # For demonstration, do nothing but refresh the UI.
            self.force_refresh()

        except Exception as e:
            self.error_message = f"Failed to mark all as read: {str(e)}"

    async def on_clear_all_notifications_pressed(self, _=None):
        """
        Clears (deletes) all notifications for the user, then refreshes the list.
        """
        try:
            user_session = self.session[UserSession]
            persistence = self.session[Persistence]

            # Placeholder for clearing notifications in the DB.
            # e.g., await persistence.clear_all_notifications(user_session.user_id)

            # For demonstration, just clear the local list:
            self.notification_data = []
            self.force_refresh()

        except Exception as e:
            self.error_message = f"Failed to clear notifications: {str(e)}"

    def build(self) -> rio.Component:
        """
        Builds the notifications page with all notification components.
        """
        notifications = [
            Notification(
                type=notif["type"],
                message=notif["message"],
                timestamp=notif["timestamp"]
            )
            for notif in self.notification_data
        ]

        return CenterComponent(
            rio.Column(
                rio.Text("Notifications", style="heading1", margin_bottom=1.5, overflow="wrap"),
                rio.Banner(text=self.error_message, style="danger", margin_bottom=1),
                rio.FlowContainer(
                    rio.Button(
                        "Mark All as Read",
                        shape="rounded",
                        on_press=self.on_mark_all_as_read_pressed,
                    ),
                    rio.Button(
                        "Clear All",
                        shape="rounded",
                        on_press=self.on_clear_all_notifications_pressed,
                    ),
                    row_spacing=0.75,
                    column_spacing=0.75,
                ),
                rio.Column(
                    *notifications if notifications else [
                        rio.Text("No notifications to display", overflow="wrap")
                    ],
                    spacing=1,
                    margin_top=1,
                ),
                spacing=1,
                margin=2,
            ),
            width_percent=WIDTH_COMFORTABLE,
        )
