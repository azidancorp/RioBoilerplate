import json
from datetime import datetime, timezone

from app.scripts import message_utils


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 7, 10, 12, 0, tzinfo=tz or timezone.utc)


def test_contact_submissions_do_not_overwrite_on_id_collision(
    tmp_path, monkeypatch
):
    notifications = []

    monkeypatch.setattr(message_utils.config, "CONTACT_SUBMISSIONS_DIR", tmp_path)
    monkeypatch.setattr(message_utils, "datetime", _FixedDateTime)
    monkeypatch.setattr(
        message_utils,
        "_notify_contact_submission",
        lambda submission: notifications.append(submission),
    )

    first = message_utils.create_contact_submission(
        name="First User",
        email="first@example.com",
        message="First message",
    )
    second = message_utils.create_contact_submission(
        name="Second User",
        email="second@example.com",
        message="Second message",
    )

    assert isinstance(first["id"], int)
    assert second["id"] == first["id"] + 1

    stored = {
        payload["id"]: payload
        for path in tmp_path.glob("contact-*.json")
        for payload in (json.loads(path.read_text(encoding="utf-8")),)
    }
    assert stored[first["id"]]["message"] == "First message"
    assert stored[second["id"]]["message"] == "Second message"
    assert len(stored) == 2
    assert len(notifications) == 2
