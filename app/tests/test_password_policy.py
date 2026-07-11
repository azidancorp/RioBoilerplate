import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import config
from app.data_models import AppUser
from app.pages.login import ResetPasswordForm, SignUpForm
from app.password_policy import evaluate_new_password, require_new_password
from app.persistence import AdminMutationContext, Persistence


STRONG_PASSWORD = "VeryStrongPass!9"
WEAK_PASSWORD = "weak"


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "password-policy.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_password_user(
    persistence: Persistence,
    *,
    email: str,
    role: str = "user",
) -> AppUser:
    user = AppUser.create_new_user_with_default_settings(
        email=email,
        password=STRONG_PASSWORD,
    )
    user.role = role
    await persistence._create_user_unchecked(user)
    return await persistence.get_user_by_id(user.id)


def test_policy_rejects_weak_password_when_disabled_even_if_acknowledged(
    monkeypatch,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)

    decision = evaluate_new_password(
        WEAK_PASSWORD,
        acknowledged_weak=True,
    )

    assert decision.ok is False
    assert decision.requires_acknowledgement is False
    assert "too weak" in (decision.message or "")


def test_policy_requires_acknowledgement_when_weak_passwords_are_enabled(
    monkeypatch,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", True)

    unacknowledged = evaluate_new_password(WEAK_PASSWORD)
    acknowledged = evaluate_new_password(
        WEAK_PASSWORD,
        acknowledged_weak=True,
    )

    assert unacknowledged.ok is False
    assert unacknowledged.requires_acknowledgement is True
    assert acknowledged.ok is True


def test_policy_never_accepts_an_empty_password(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", True)

    decision = evaluate_new_password("", acknowledged_weak=True)

    assert decision.ok is False
    with pytest.raises(ValueError, match="enter a password"):
        require_new_password("", acknowledged_weak=True)


@pytest.mark.parametrize("operation", ["update", "reset"])
def test_persistence_rejects_weak_password_when_disabled_without_side_effects(
    temp_db: Persistence,
    monkeypatch,
    operation: str,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)

    async def scenario():
        user = await _create_password_user(
            temp_db,
            email=f"strict-{operation}@example.com",
        )
        session = await temp_db.create_session(user.id)
        reset_token = await temp_db.create_reset_token(user.id)

        with pytest.raises(ValueError, match="too weak"):
            if operation == "update":
                await temp_db.update_password(
                    user.id,
                    WEAK_PASSWORD,
                    acknowledged_weak=True,
                )
            else:
                await temp_db.consume_reset_token_and_update_password(
                    reset_token.token,
                    user.id,
                    WEAK_PASSWORD,
                    acknowledged_weak=True,
                )

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(STRONG_PASSWORD)
        assert not refreshed.verify_password(WEAK_PASSWORD)
        assert (await temp_db.get_session_by_auth_token(session.id)).user_id == user.id
        assert (await temp_db.get_user_by_reset_token(reset_token.token)).id == user.id

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["update", "reset"])
def test_persistence_accepts_acknowledged_weak_password_when_enabled(
    temp_db: Persistence,
    monkeypatch,
    operation: str,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", True)

    async def scenario():
        user = await _create_password_user(
            temp_db,
            email=f"allowed-{operation}@example.com",
        )
        if operation == "update":
            await temp_db.update_password(
                user.id,
                WEAK_PASSWORD,
                acknowledged_weak=True,
            )
        else:
            reset_token = await temp_db.create_reset_token(user.id)
            assert await temp_db.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                WEAK_PASSWORD,
                acknowledged_weak=True,
            )

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(WEAK_PASSWORD)

    asyncio.run(scenario())


def test_admin_creation_uses_the_same_password_policy(
    temp_db: Persistence,
    monkeypatch,
):
    async def scenario():
        root = await _create_password_user(
            temp_db,
            email="password-policy-root@example.com",
            role="root",
        )
        root_session = await temp_db.create_session(root.id)
        context = AdminMutationContext(auth_token=root_session.id)

        monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)
        with pytest.raises(ValueError, match="too weak"):
            await temp_db.admin_create_user(
                email="strict-admin-created@example.com",
                password=WEAK_PASSWORD,
                role="user",
                admin_context=context,
                acknowledged_weak=True,
            )
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("strict-admin-created@example.com")

        monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", True)
        created = await temp_db.admin_create_user(
            email="allowed-admin-created@example.com",
            password=WEAK_PASSWORD,
            role="user",
            admin_context=context,
            acknowledged_weak=True,
        )
        assert created.verify_password(WEAK_PASSWORD)

    asyncio.run(scenario())


def test_signup_wiring_does_not_let_acknowledgement_override_strict_policy(
    temp_db: Persistence,
    monkeypatch,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)

    class PersistenceSession:
        def __getitem__(self, key):
            if key is Persistence:
                return temp_db
            raise KeyError(key)

    form = SimpleNamespace(
        session=PersistenceSession(),
        email="strict-signup@example.com",
        password=WEAK_PASSWORD,
        confirm_password=WEAK_PASSWORD,
        referral_code="",
        banner_style="danger",
        error_message="",
        passwords_valid=False,
        is_email_valid=False,
        acknowledge_weak_password=True,
    )
    asyncio.run(SignUpForm.on_sign_up_pressed(form))

    assert "too weak" in form.error_message
    assert temp_db.get_user_count() == 0


def test_reset_wiring_does_not_let_acknowledgement_override_strict_policy(
    monkeypatch,
):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)
    form = SimpleNamespace(
        email="strict-reset@example.com",
        reset_token="ValidResetToken123",
        new_password=WEAK_PASSWORD,
        confirm_password=WEAK_PASSWORD,
        acknowledge_weak_password=True,
        banner_style="danger",
        error_message="",
    )

    def set_banner(style: str, message: str) -> None:
        form.banner_style = style
        form.error_message = message

    form._set_banner = set_banner
    asyncio.run(ResetPasswordForm._update_password(form))

    assert form.banner_style == "danger"
    assert "too weak" in form.error_message
