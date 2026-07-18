import json
import stat
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

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


def test_resend_sends_expected_payload_without_fallback(tmp_path, monkeypatch):
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"id": "email-123"}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "resend")
    monkeypatch.setattr(message_utils.config, "RESEND_API_KEY", "re_test")
    monkeypatch.setattr(message_utils, "_EMAIL_OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(message_utils.requests, "post", fake_post)

    message_utils.send_email(
        recipient="user@example.com",
        sender="sender@example.com",
        subject="Test subject",
        body="Test body",
    )

    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["headers"]["Authorization"] == "Bearer re_test"
    assert captured["headers"]["User-Agent"] == "rio-boilerplate"
    assert captured["json"] == {
        "from": "sender@example.com",
        "to": ["user@example.com"],
        "subject": "Test subject",
        "text": "Test body",
    }
    assert captured["timeout"] == 10
    assert not list(tmp_path.iterdir())


def test_resend_requires_api_key_before_network_access(monkeypatch):
    network_called = False

    def fake_post(*args, **kwargs):
        nonlocal network_called
        network_called = True
        raise AssertionError("network should not be called")

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "resend")
    monkeypatch.setattr(message_utils.config, "RESEND_API_KEY", "")
    monkeypatch.setattr(message_utils.requests, "post", fake_post)

    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            recipient="user@example.com",
            sender="sender@example.com",
            subject="Test",
            body="Body",
        )

    assert exc_info.value.status_code == 500
    assert network_called is False


def test_resend_failure_raises_without_leaking_key_or_writing_outbox(
    tmp_path,
    monkeypatch,
    caplog,
):
    api_key = "re_secret\nInjected: yes"

    def fail_post(*args, **kwargs):
        raise message_utils.requests.exceptions.InvalidHeader(
            f"Invalid Authorization header: Bearer {api_key}"
        )

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "resend")
    monkeypatch.setattr(message_utils.config, "RESEND_API_KEY", api_key)
    monkeypatch.setattr(message_utils, "_EMAIL_OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(message_utils.requests, "post", fail_post)

    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            recipient="user@example.com",
            sender="sender@example.com",
            subject="Test",
            body="sensitive-token",
        )

    assert exc_info.value.status_code == 502
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert api_key not in caplog.text
    assert not list(tmp_path.iterdir())


def test_smtp_uses_verified_tls_before_authentication(monkeypatch):
    events = []
    tls_context = object()

    class SMTP:
        def __init__(self, host, port, timeout):
            events.append(("connect", host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def starttls(self, *, context):
            events.append(("starttls", context))

        def login(self, username, password):
            events.append(("login", username, password))

        def send_message(self, message):
            events.append(("send", message["To"]))

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "smtp")
    monkeypatch.setattr(message_utils.config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(message_utils.config, "SMTP_PORT", 587)
    monkeypatch.setattr(message_utils.config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(message_utils.config, "SMTP_USERNAME", "smtp-user")
    monkeypatch.setattr(message_utils.config, "SMTP_PASSWORD", " smtp-password ")
    monkeypatch.setattr(message_utils.ssl, "create_default_context", lambda: tls_context)
    monkeypatch.setattr(message_utils.smtplib, "SMTP", SMTP)

    message_utils.send_email(
        recipient="user@example.com",
        sender="sender@example.com",
        subject="Test",
        body="Body",
    )

    assert events == [
        ("connect", "smtp.example.com", 587, 10),
        ("starttls", tls_context),
        ("login", "smtp-user", " smtp-password "),
        ("send", "user@example.com"),
    ]


def test_smtp_rejects_insecure_or_partial_credentials_before_connect(monkeypatch):
    connected = False

    def fake_smtp(*args, **kwargs):
        nonlocal connected
        connected = True
        raise AssertionError("SMTP should not be contacted")

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "smtp")
    monkeypatch.setattr(message_utils.config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(message_utils.config, "SMTP_USE_TLS", False)
    monkeypatch.setattr(message_utils.config, "SMTP_USERNAME", "smtp-user")
    monkeypatch.setattr(message_utils.config, "SMTP_PASSWORD", "smtp-password")
    monkeypatch.setattr(message_utils.smtplib, "SMTP", fake_smtp)

    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            recipient="user@example.com",
            sender="sender@example.com",
            subject="Test",
            body="Body",
        )
    assert exc_info.value.status_code == 500
    assert connected is False

    monkeypatch.setattr(message_utils.config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(message_utils.config, "SMTP_PASSWORD", "")
    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            recipient="user@example.com",
            sender="sender@example.com",
            subject="Test",
            body="Body",
        )
    assert exc_info.value.status_code == 500
    assert connected is False


def test_smtp_failure_does_not_retain_secret_or_write_outbox(
    tmp_path,
    monkeypatch,
    caplog,
):
    password = " smtp-secret "

    class SMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def starttls(self, *, context):
            return None

        def login(self, username, supplied_password):
            auth_value = f"\0{username}\0{supplied_password}"
            raise UnicodeEncodeError(
                "ascii",
                auth_value,
                0,
                len(auth_value),
                "test authentication failure",
            )

        def send_message(self, message):
            raise AssertionError("message must not be sent after failed authentication")

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "smtp")
    monkeypatch.setattr(message_utils.config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(message_utils.config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(message_utils.config, "SMTP_USERNAME", "smtp-user")
    monkeypatch.setattr(message_utils.config, "SMTP_PASSWORD", password)
    monkeypatch.setattr(message_utils, "_EMAIL_OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(message_utils.smtplib, "SMTP", SMTP)

    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            recipient="user@example.com",
            sender="sender@example.com",
            subject="Test",
            body="sensitive-token",
        )

    assert exc_info.value.status_code == 502
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert password not in caplog.text
    assert not list(tmp_path.iterdir())


def test_outbox_rejects_legacy_smtp_host_without_network_or_token_file(
    tmp_path,
    monkeypatch,
    caplog,
):
    network_calls = []

    def fail_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("External delivery must not be inferred")

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "outbox")
    monkeypatch.setattr(message_utils.config, "SMTP_HOST", "smtp.legacy.example")
    monkeypatch.setattr(message_utils, "_EMAIL_OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(message_utils.requests, "post", fail_network)
    monkeypatch.setattr(message_utils.smtplib, "SMTP", fail_network)

    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            "user@example.com",
            "Reset",
            "sensitive-reset-token",
        )

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == "Email delivery is not configured."
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert network_calls == []
    assert not list(tmp_path.iterdir())
    assert "sensitive-reset-token" not in caplog.text
    assert "EMAIL_METHOD='outbox'" in caplog.text
    assert "SMTP_HOST" in caplog.text


@pytest.mark.parametrize("smtp_host", ["", "   "])
def test_development_outbox_is_private_and_collision_safe(
    tmp_path,
    monkeypatch,
    smtp_host,
):
    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "outbox")
    monkeypatch.setattr(message_utils.config, "SMTP_HOST", smtp_host)
    monkeypatch.setattr(message_utils, "_EMAIL_OUTBOX_DIR", tmp_path)
    monkeypatch.setattr(message_utils, "datetime", _FixedDateTime)

    message_utils.send_email("same@example.com", "First", "first-token")
    message_utils.send_email("same@example.com", "Second", "second-token")

    files = list(tmp_path.glob("*.txt"))
    assert len(files) == 2
    contents = {path.read_text(encoding="utf-8") for path in files}
    assert any("Subject: First" in content and "first-token" in content for content in contents)
    assert any("Subject: Second" in content and "second-token" in content for content in contents)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files)


def test_outbox_disabled_for_message_and_unknown_method_fail_closed(monkeypatch):
    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "outbox")
    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email(
            "user@example.com",
            "Test",
            "Body",
            persist_copy=False,
        )
    assert exc_info.value.status_code == 500

    monkeypatch.setattr(message_utils.config, "EMAIL_METHOD", "unexpected")
    with pytest.raises(HTTPException) as exc_info:
        message_utils.send_email("user@example.com", "Test", "Body")
    assert exc_info.value.status_code == 500
