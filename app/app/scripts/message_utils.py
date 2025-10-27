"""Utilities for handling contact form notifications and persistence."""

from __future__ import annotations

import json
import logging
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from fastapi import HTTPException, status

from app.validation import SecuritySanitizer

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "contact_messages"
_EMAIL_OUTBOX_DIR = Path(__file__).resolve().parent.parent / "data" / "email_outbox"


def create_contact_submission(name: str, email: str, message: str) -> Dict[str, Any]:
    """Validate, persist, and notify about a contact submission."""
    sanitized_name = SecuritySanitizer.sanitize_string(name, max_length=100)
    if not sanitized_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide a valid name.",
        )

    sanitized_message = SecuritySanitizer.sanitize_string(message, max_length=10000)
    if not sanitized_message:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide a valid message.",
        )

    sanitized_email = SecuritySanitizer.validate_email_format(email)

    try:
        entry = _persist_contact_submission(
            name=sanitized_name,
            email=sanitized_email,
            message=sanitized_message,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store contact submission.",
        ) from exc

    return {"message": "Contact request saved successfully", **entry}


def _persist_contact_submission(name: str, email: str, message: str) -> Dict[str, int]:
    timestamp = datetime.now(timezone.utc)
    entry_id = int(timestamp.timestamp() * 1000)

    submission = {
        "id": entry_id,
        "name": name,
        "email": email,
        "message": message,
        "timestamp": timestamp.isoformat(),
    }

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    file_path = _DATA_DIR / f"contact-{entry_id}.json"

    with file_path.open("w", encoding="utf-8") as handle:
        json.dump(submission, handle, indent=2)

    _notify_contact_submission(submission)

    return {"id": entry_id}


def _notify_contact_submission(submission: Dict[str, Any]) -> None:
    subject = "New contact form submission"
    body = (
        f"Name: {submission['name']}\n"
        f"Email: {submission['email']}\n"
        f"Message: {submission['message']}\n"
        f"Timestamp: {submission['timestamp']}\n"
        f"ID: {submission['id']}"
    )

    send_ntfy_message(
        message=f"{subject}\n\n{body}",
        channel=os.getenv("RIO_CONTACT_NTFY_CHANNEL"),
        priority=os.getenv("RIO_CONTACT_NTFY_PRIORITY"),
    )


def send_email(
    recipient: str,
    subject: str,
    body: str,
    *,
    sender: Optional[str] = None,
    persist_copy: bool = True,
) -> None:
    """
    Send a plain text email using basic SMTP configuration with a local outbox fallback.

    When no SMTP settings are provided, the message is persisted to the data/email_outbox
    directory so testers can inspect outbound mail during development.
    """
    sanitized_recipient = SecuritySanitizer.validate_email_format(recipient)

    subject = (subject or "").strip()
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email subject must not be empty.",
        )

    sender_address = (sender or os.getenv("RIO_DEFAULT_EMAIL_SENDER") or "no-reply@rio.local").strip()
    if not sender_address:
        sender_address = "no-reply@rio.local"

    message = EmailMessage()
    message["To"] = sanitized_recipient
    message["From"] = sender_address
    message["Subject"] = subject
    message.set_content(body)

    smtp_host = os.getenv("RIO_SMTP_HOST")
    if smtp_host:
        smtp_port = int(os.getenv("RIO_SMTP_PORT", "587"))
        username = os.getenv("RIO_SMTP_USERNAME")
        password = os.getenv("RIO_SMTP_PASSWORD")
        use_tls = os.getenv("RIO_SMTP_USE_TLS", "true").lower() not in {"0", "false", "no"}

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
                if use_tls:
                    smtp.starttls()
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
                logger.info("Sent email via SMTP to %s", sanitized_recipient)
                return
        except Exception as exc:
            logger.error("Failed to send email via SMTP: %s", exc)

    if persist_copy:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        sanitized_filename = sanitized_recipient.replace("@", "_at_").replace(".", "_")
        _EMAIL_OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
        outbox_path = _EMAIL_OUTBOX_DIR / f"{timestamp}-{sanitized_filename}.txt"

        try:
            with outbox_path.open("w", encoding="utf-8") as handle:
                handle.write(f"To: {sanitized_recipient}\n")
                handle.write(f"From: {sender_address}\n")
                handle.write(f"Subject: {subject}\n\n")
                handle.write(body)
            logger.info("Email saved to local outbox: %s", outbox_path)
        except OSError as exc:
            logger.error("Failed to persist email to outbox: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to queue email for delivery.",
            ) from exc


def send_ntfy_message(
    message: str,
    *,
    channel: Optional[str] = None,
    priority: Optional[str] = None,
) -> None:
    """Send a notification to an ntfy topic.

    Security: This function requires explicit configuration via environment variables.
    When RIO_CONTACT_NTFY_CHANNEL is not set, notifications are disabled to prevent
    accidental data leaks to public ntfy channels.
    """
    # Security: Require explicit channel configuration to prevent PII leaks
    if not channel:
        logger.warning(
            "NTFY NOTIFICATIONS DISABLED: RIO_CONTACT_NTFY_CHANNEL environment variable "
            "is not set. Contact form submissions will be saved locally but no notifications "
            "will be sent. Set RIO_CONTACT_NTFY_CHANNEL to enable ntfy notifications."
        )
        return

    target_channel = channel
    target_priority = priority or "default"

    try:
        requests.post(
            f"https://ntfy.sh/{target_channel}",
            data=message.encode("utf-8"),
            headers={"Priority": target_priority},
            timeout=10,
        )
        logger.info(f"Notification sent to ntfy channel: {target_channel}")
    except Exception as e:
        # Swallow exceptions so downstream workflows do not fail.
        logger.error(f"Failed to send ntfy message: {e}")
        pass
