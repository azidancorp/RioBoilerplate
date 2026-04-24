import pytest
from fastapi import HTTPException

from app.validation import SecuritySanitizer


def test_email_validation_normalizes_common_addresses():
    assert (
        SecuritySanitizer.validate_email_format(" USER@Example.COM ", require_valid=True)
        == "user@example.com"
    )


def test_email_validation_uses_idna_normalization_for_ascii_domains():
    assert (
        SecuritySanitizer.validate_email_format("me@Ｄｏｍａｉｎ.com", require_valid=True)
        == "me@domain.com"
    )


@pytest.mark.parametrize(
    "email",
    [
        "user@xn--pple-43d.com",
        "user@аррӏе.com",
        "uѕer@example.com",
    ],
)
def test_email_validation_rejects_idn_and_unicode_homograph_inputs(email):
    with pytest.raises(HTTPException):
        SecuritySanitizer.validate_email_format(email, require_valid=True)


def test_email_validation_can_still_allow_username_mode_identifiers():
    assert (
        SecuritySanitizer.validate_email_format(" UserName ", require_valid=False)
        == "username"
    )


def test_email_validation_checks_suspicious_patterns_even_without_email_mode():
    with pytest.raises(HTTPException):
        SecuritySanitizer.validate_email_format("javascript:alert(1)", require_valid=False)
