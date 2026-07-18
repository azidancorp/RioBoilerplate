"""Utilities for handling contact form notifications and persistence."""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import tempfile
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests
from fastapi import HTTPException, status

from app.config import config
from app.validation import SecuritySanitizer

logger = logging.getLogger(__name__)

_EMAIL_OUTBOX_DIR = Path(__file__).resolve().parent.parent / "data" / "email_outbox"
_RESEND_EMAILS_URL = "https://api.resend.com/emails"
_MAX_CONTACT_ID_ATTEMPTS = 1000


def _email_configuration_error(log_detail: str) -> HTTPException:
    logger.error("Email delivery configuration error: %s", log_detail)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Email delivery is not configured.",
    )


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
    initial_entry_id = int(timestamp.timestamp() * 1000)
    data_dir = Path(config.CONTACT_SUBMISSIONS_DIR).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)

    for offset in range(_MAX_CONTACT_ID_ATTEMPTS):
        entry_id = initial_entry_id + offset
        submission = {
            "id": entry_id,
            "name": name,
            "email": email,
            "message": message,
            "timestamp": timestamp.isoformat(),
        }
        file_path = data_dir / f"contact-{entry_id}.json"

        try:
            with file_path.open("x", encoding="utf-8") as handle:
                json.dump(submission, handle, indent=2)
        except FileExistsError:
            continue

        _notify_contact_submission(submission)
        return {"id": entry_id}

    raise OSError("Unable to allocate a unique contact submission ID.")


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
        channel=config.CONTACT_NTFY_CHANNEL,
        priority=config.CONTACT_NTFY_PRIORITY,
    )


# TODO: Move reset/verification email bodies to Jinja templates with render tests.
def send_email_verification_email(
    *,
    recipient: str,
    token: str,
    valid_until: datetime,
) -> None:
    """
    Send account email-verification instructions.
    """
    app_url = (config.APP_URL or "http://localhost:8000").rstrip("/")
    verify_link = f"{app_url}/login?verify_token={quote(token)}"
    body = (
        "Hi,\n\n"
        "Please verify your account email address.\n\n"
        f"Verification link: {verify_link}\n\n"
        f"Verification token (if you need to paste it manually): {token}\n\n"
        f"This link/token expires on {valid_until.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
        "If you did not create this account, you can ignore this email."
    )
    send_email(
        recipient=recipient,
        subject="Verify your Rio account email",
        body=body,
    )


def send_password_reset_email(
    *,
    recipient: str,
    token: str,
    valid_until: datetime,
) -> None:
    """
    Send password-reset instructions.
    """
    app_url = (config.APP_URL or "http://localhost:8000").rstrip("/")
    reset_link = f"{app_url}/login?reset_token={quote(token)}"
    body = (
        "Hi,\n\n"
        "You requested a password reset.\n\n"
        f"Reset link: {reset_link}\n\n"
        f"Reset token (if you need to paste it manually): {token}\n\n"
        f"This link/token expires on {valid_until.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.\n\n"
        "If you did not request this reset, you can ignore this email."
    )
    send_email(
        recipient=recipient,
        subject="Reset your Rio password",
        body=body,
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
    Send plain text email using the explicitly configured delivery method.

    The local outbox is a development inspection aid, not a delivery queue. External
    provider failures are reported to the caller and never fall back to local files.
    """
    sanitized_recipient = SecuritySanitizer.validate_email_format(
        recipient,
        require_valid=True,
    )

    subject = (subject or "").strip()
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Email subject must not be empty.",
        )

    sender_address = (sender or config.DEFAULT_EMAIL_SENDER or "no-reply@rio.local").strip()
    if not sender_address:
        sender_address = "no-reply@rio.local"

    method = (config.EMAIL_METHOD or "").strip().lower()

    if method == "resend":
        api_key = (config.RESEND_API_KEY or "").strip()
        if not api_key:
            raise _email_configuration_error(
                "EMAIL_METHOD='resend' requires RESEND_API_KEY."
            )

        try:
            external_sender = SecuritySanitizer.validate_email_format(
                sender_address,
                require_valid=True,
            )
        except HTTPException as exc:
            raise _email_configuration_error(
                "External delivery requires a valid DEFAULT_EMAIL_SENDER."
            ) from exc

        delivery_failure_type: str | None = None
        try:
            response = requests.post(
                _RESEND_EMAILS_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "User-Agent": "rio-boilerplate",
                },
                json={
                    "from": external_sender,
                    "to": [sanitized_recipient],
                    "subject": subject,
                    "text": body,
                },
                timeout=10,
            )
            response.raise_for_status()
            response_data = response.json()
            email_id = response_data.get("id") if isinstance(response_data, dict) else None
            if not email_id:
                raise ValueError("Resend response did not include an email ID.")
        except (requests.RequestException, ValueError) as exc:
            delivery_failure_type = type(exc).__name__

        if delivery_failure_type is not None:
            logger.error("Resend email delivery failed (%s).", delivery_failure_type)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Email delivery is temporarily unavailable.",
            )

        logger.info(
            "Sent email via Resend to %s (id=%s)",
            sanitized_recipient,
            email_id,
        )
        return

    if method == "smtp":
        smtp_host = (config.SMTP_HOST or "").strip()
        username = (config.SMTP_USERNAME or "").strip()
        password = config.SMTP_PASSWORD or ""

        if not smtp_host:
            raise _email_configuration_error("EMAIL_METHOD='smtp' requires SMTP_HOST.")
        if not config.SMTP_USE_TLS:
            raise _email_configuration_error("EMAIL_METHOD='smtp' requires TLS.")
        if bool(username) != bool(password):
            raise _email_configuration_error(
                "SMTP username and password must be configured together."
            )

        try:
            external_sender = SecuritySanitizer.validate_email_format(
                sender_address,
                require_valid=True,
            )
        except HTTPException as exc:
            raise _email_configuration_error(
                "External delivery requires a valid DEFAULT_EMAIL_SENDER."
            ) from exc

        message = EmailMessage()
        message["To"] = sanitized_recipient
        message["From"] = external_sender
        message["Subject"] = subject
        message.set_content(body)

        delivery_failure_type = None
        try:
            with smtplib.SMTP(smtp_host, config.SMTP_PORT, timeout=10) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
        except Exception as exc:
            delivery_failure_type = type(exc).__name__

        if delivery_failure_type is not None:
            logger.error("SMTP email delivery failed (%s).", delivery_failure_type)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Email delivery is temporarily unavailable.",
            )

        logger.info("Sent email via SMTP to %s", sanitized_recipient)
        return

    if method == "outbox":
        if (config.SMTP_HOST or "").strip():
            raise _email_configuration_error(
                "EMAIL_METHOD='outbox' cannot be used while SMTP_HOST is configured; "
                "set EMAIL_METHOD='smtp' or clear SMTP_HOST."
            )

        if not persist_copy:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="The development email outbox is disabled for this message.",
            )

        outbox_path: Path | None = None
        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            _EMAIL_OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=_EMAIL_OUTBOX_DIR,
                prefix=f"{timestamp}-",
                suffix=".txt",
                delete=False,
            ) as handle:
                outbox_path = Path(handle.name)
                handle.write(f"To: {sanitized_recipient}\n")
                handle.write(f"From: {sender_address}\n")
                handle.write(f"Subject: {subject}\n\n")
                handle.write(body)
            logger.info("Email saved to local outbox: %s", outbox_path)
        except OSError as exc:
            if outbox_path is not None:
                try:
                    outbox_path.unlink(missing_ok=True)
                except OSError:
                    logger.warning("Failed to remove partial outbox file: %s", outbox_path)
            logger.error("Failed to persist email to outbox: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to save email to the development outbox.",
            ) from exc
        return

    raise _email_configuration_error(
        f"Unsupported EMAIL_METHOD '{method}'; use outbox, resend, or smtp."
    )


def send_ntfy_message(
    message: str,
    *,
    channel: Optional[str] = None,
    priority: Optional[str] = None,
) -> None:
    """Send a notification to an ntfy topic.

    Security: This function requires explicit channel configuration.
    When CONTACT_NTFY_CHANNEL is not set, notifications are disabled to prevent
    accidental data leaks to public ntfy channels.
    """
    # Security: Require explicit channel configuration to prevent PII leaks
    if not channel:
        logger.warning(
            "NTFY NOTIFICATIONS DISABLED: CONTACT_NTFY_CHANNEL is not configured. "
            "Contact form submissions will be saved locally but no notifications "
            "will be sent."
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
