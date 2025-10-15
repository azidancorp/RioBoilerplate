"""Utilities for handling contact form notifications and persistence."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from fastapi import HTTPException, status

from app.validation import SecuritySanitizer

DEFAULT_NTFY_CHANNEL = "rioboilerplate"
DEFAULT_NTFY_PRIORITY = "max"

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "contact_messages"


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


def send_ntfy_message(
    message: str,
    *,
    channel: Optional[str] = None,
    priority: Optional[str] = None,
) -> None:
    """Send a notification to an ntfy topic."""
    target_channel = channel or DEFAULT_NTFY_CHANNEL
    target_priority = priority or DEFAULT_NTFY_PRIORITY

    try:
        requests.post(
            f"https://ntfy.sh/{target_channel}",
            data=message.encode("utf-8"),
            headers={"Priority": target_priority},
            timeout=10,
        )
    except Exception:
        # Swallow exceptions so downstream workflows do not fail.
        print("Failed to send ntfy message.")
        pass
