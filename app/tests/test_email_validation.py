import asyncio

import pytest
from fastapi import HTTPException

from app.config import config
from app.data_models import AppUser
from app.persistence import Persistence
from app.validation import SecuritySanitizer


@pytest.fixture(autouse=True)
def reset_email_validation_config():
    original_require_valid_email = config.REQUIRE_VALID_EMAIL
    yield
    config.REQUIRE_VALID_EMAIL = original_require_valid_email


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


def test_create_user_stores_normalized_email(tmp_path):
    persistence = Persistence(db_path=tmp_path / "email-normalization.db")
    try:
        user = AppUser.create_new_user_with_default_settings(
            email="me@Ｄｏｍａｉｎ.com",
            password="password",
        )

        async def scenario():
            await persistence._create_user_unchecked(user)
            stored_user = await persistence.get_user_by_email("me@domain.com")
            assert stored_user.email == "me@domain.com"

        asyncio.run(scenario())
    finally:
        persistence.close()


def test_create_user_applies_relaxed_identifier_safety_checks(tmp_path):
    config.REQUIRE_VALID_EMAIL = False
    persistence = Persistence(db_path=tmp_path / "relaxed-email-validation.db")
    try:
        user = AppUser.create_new_user_with_default_settings(
            email=" UserName ",
            password="password",
        )
        dangerous_user = AppUser.create_new_user_with_default_settings(
            email="javascript:alert(1)",
            password="password",
        )

        async def scenario():
            await persistence._create_user_unchecked(user)
            stored_user = await persistence.get_user_by_email("username")
            assert stored_user.email == "username"

            with pytest.raises(HTTPException):
                await persistence._create_user_unchecked(dangerous_user)

        asyncio.run(scenario())
    finally:
        persistence.close()
