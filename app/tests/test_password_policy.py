import asyncio
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import config
from app.data_models import AppUser
from app.pages.login import ResetPasswordForm, SignUpForm
from app.password_policy import (
    evaluate_bootstrap_password,
    evaluate_new_password,
    require_new_password,
)
from app.persistence import AdminMutationContext, Persistence


STRONG_PASSWORD = "VeryStrongPass!9"
SHORT_PASSWORD = "password123"
LOW_SCORE_PASSWORD = "alllowercasephrase"


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


@pytest.mark.parametrize(
    ("password", "expected_passwords", "warning_code"),
    [
        ("weak", (), "too_short"),
        (LOW_SCORE_PASSWORD, (), "low_strength"),
        ("password1234567", (), "common_password"),
        ("zq" * 8, (), "repeated_pattern"),
        ("bcdefghijklmnopq", (), "sequential_pattern"),
        (
            "uniquehandle123456",
            ("uniquehandle",),
            "account_derived",
        ),
        (
            "owner@example.comA",
            ("owner@example.com",),
            "account_derived",
        ),
        (
            "ALongAccountIdentifier2026Z",
            ("LongAccountIdentifier2026",),
            "account_derived",
        ),
        ("rio-boilerplate-passwordx", (), "common_password"),
        ("     ", (), "whitespace_only"),
        ("Azidanx" + " " * 8, (), "surrounding_whitespace"),
        ("\u200b" * 15, (), "invisible_characters"),
        ("\u0301" * 15, (), "no_visible_characters"),
        ("\x00" * 15, (), "control_characters"),
        ("ｐａｓｓｗｏｒｄ１２３４５６７８９", (), "common_password"),
        ("x" * (config.MAX_PASSWORD_LENGTH + 1), (), "too_long"),
    ],
)
def test_every_quality_finding_warns_then_accepts_after_acknowledgement(
    password: str,
    expected_passwords: tuple[str, ...],
    warning_code: str,
):
    unacknowledged = evaluate_new_password(
        password,
        expected_passwords=expected_passwords,
    )
    acknowledged = evaluate_new_password(
        password,
        acknowledged_weak=True,
        expected_passwords=expected_passwords,
    )

    assert unacknowledged.ok is False
    assert unacknowledged.requires_acknowledgement is True
    assert warning_code in {warning.code for warning in unacknowledged.warnings}
    assert "acknowledge" in (unacknowledged.message or "")
    with pytest.raises(ValueError, match="acknowledge"):
        require_new_password(password, expected_passwords=expected_passwords)

    assert acknowledged.ok is True
    assert acknowledged.requires_acknowledgement is False
    assert acknowledged.warnings == unacknowledged.warnings
    assert acknowledged.message is None
    assert require_new_password(
        password,
        acknowledged_weak=True,
        expected_passwords=expected_passwords,
    ) == acknowledged.strength


@pytest.mark.parametrize(
    ("password", "expected_passwords"),
    [
        (
            "owner@example.comAlphabeticWord",
            ("owner@example.com",),
        ),
        ("bluecorrecthorsebatterystaplegreen", ()),
        (
            "myLongAccountIdentifier2026Value",
            ("LongAccountIdentifier2026",),
        ),
    ],
)
def test_alphabetic_derivative_check_does_not_become_substring_matching(
    password: str,
    expected_passwords: tuple[str, ...],
):
    decision = evaluate_new_password(
        password,
        expected_passwords=expected_passwords,
    )

    assert {warning.code for warning in decision.warnings}.isdisjoint(
        {"account_derived", "common_password"}
    )


@pytest.mark.parametrize(
    "password",
    ["!!!!!", "     ", "password123", "123456789012", "!!!!!!!!!!!!!!!"],
)
def test_warned_passwords_never_display_as_recommended(password: str):
    decision = evaluate_new_password(password)

    assert decision.ok is False
    assert decision.strength < config.PASSWORD_STRENGTH_WARNING_THRESHOLD


def test_normal_policy_api_has_no_bypass_or_score_authorization_parameters():
    evaluate_parameters = inspect.signature(evaluate_new_password).parameters
    require_parameters = inspect.signature(require_new_password).parameters

    assert "acknowledged_weak" in evaluate_parameters
    assert "acknowledged_weak" in require_parameters
    for obsolete_parameter in ("allow_weak", "minimum_strength"):
        assert obsolete_parameter not in evaluate_parameters
        assert obsolete_parameter not in require_parameters


def test_strong_password_without_warnings_needs_no_acknowledgement():
    decision = evaluate_new_password(STRONG_PASSWORD)

    assert decision.ok is True
    assert decision.requires_acknowledgement is False
    assert decision.warnings == ()
    assert decision.message is None


@pytest.mark.parametrize("password", ["", "\ud800" * 15])
def test_form_or_technical_failure_cannot_be_acknowledged(password: str):
    decision = evaluate_new_password(password, acknowledged_weak=True)

    assert decision.ok is False
    assert decision.requires_acknowledgement is False
    assert decision.warnings == ()
    with pytest.raises(ValueError):
        require_new_password(password, acknowledged_weak=True)


def test_operator_strict_mode_rejects_warnings_even_when_acknowledged(monkeypatch):
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)

    decision = evaluate_new_password("weak", acknowledged_weak=True)

    assert decision.ok is False
    assert decision.requires_acknowledgement is False
    assert decision.warnings
    assert "does not allow" in (decision.message or "")


def test_bootstrap_flag_is_an_acknowledgement_not_a_technical_bypass(monkeypatch):
    with pytest.raises(TypeError, match="must be a bool"):
        evaluate_bootstrap_password(
            SHORT_PASSWORD,
            allow_insecure_password="false",  # type: ignore[arg-type]
        )

    for password in (
        SHORT_PASSWORD,
        "     ",
        "\u200b" * config.MIN_PASSWORD_LENGTH,
        "\x00" * config.MIN_PASSWORD_LENGTH,
        "x" * (config.MAX_PASSWORD_LENGTH + 1),
    ):
        assert evaluate_bootstrap_password(
            password,
            allow_insecure_password=False,
        ).requires_acknowledgement
        assert evaluate_bootstrap_password(
            password,
            allow_insecure_password=True,
        ).ok

    assert not evaluate_bootstrap_password(
        "",
        allow_insecure_password=True,
    ).ok
    assert not evaluate_bootstrap_password(
        "\ud800",
        allow_insecure_password=True,
    ).ok

    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)
    assert not evaluate_bootstrap_password(
        SHORT_PASSWORD,
        allow_insecure_password=True,
    ).ok


def test_spaces_inside_a_long_passphrase_are_allowed():
    password = "Quiet amber fox"
    assert len(password) == config.MIN_PASSWORD_LENGTH

    assert evaluate_new_password(password).ok is True


def test_unicode_marks_used_by_writing_systems_count_toward_length():
    password = "नमस्ते सुरक्षित"
    assert len(password) == config.MIN_PASSWORD_LENGTH

    assert evaluate_new_password(password).ok is True


def test_canonically_equivalent_account_identifier_warns():
    decision = evaluate_new_password(
        "cafe\u0301-utilisateur",
        expected_passwords=["café-utilisateur"],
    )

    assert decision.ok is False
    assert decision.requires_acknowledgement is True
    assert decision.warnings


def test_oversized_password_warns_without_running_the_scorer(monkeypatch):
    def fail_if_scored(*_args, **_kwargs):
        raise AssertionError("Oversized passwords must fail before scoring")

    monkeypatch.setattr("app.password_policy.get_password_strength", fail_if_scored)
    password = "x" * (config.MAX_PASSWORD_LENGTH + 1)
    decision = evaluate_new_password(password)
    accepted = evaluate_new_password(password, acknowledged_weak=True)

    assert decision.ok is False
    assert decision.requires_acknowledgement is True
    assert decision.strength == 0
    assert {warning.code for warning in decision.warnings} == {"too_long"}
    assert accepted.ok is True


@pytest.mark.parametrize("operation", ["update", "reset"])
def test_persistence_requires_acknowledgement_without_side_effects(
    temp_db: Persistence,
    operation: str,
):
    async def scenario():
        user = await _create_password_user(
            temp_db,
            email=f"strict-{operation}@example.com",
        )
        session = await temp_db.create_session(user.id)
        reset_token = await temp_db.create_reset_token(user.id)

        with pytest.raises(ValueError, match="acknowledge"):
            if operation == "update":
                await temp_db.update_password(
                    user.id,
                    SHORT_PASSWORD,
                )
            else:
                await temp_db.consume_reset_token_and_update_password(
                    reset_token.token,
                    user.id,
                    SHORT_PASSWORD,
                )

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(STRONG_PASSWORD)
        assert not refreshed.verify_password(SHORT_PASSWORD)
        assert (await temp_db.get_session_by_auth_token(session.id)).user_id == user.id
        assert (await temp_db.get_user_by_reset_token(reset_token.token)).id == user.id

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["update", "reset"])
def test_persistence_accepts_password_regardless_of_display_score(
    temp_db: Persistence,
    operation: str,
):
    async def scenario():
        user = await _create_password_user(
            temp_db,
            email=f"allowed-{operation}@example.com",
        )
        if operation == "update":
            await temp_db.update_password(
                user.id,
                LOW_SCORE_PASSWORD,
                acknowledged_weak=True,
            )
        else:
            reset_token = await temp_db.create_reset_token(user.id)
            assert await temp_db.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                LOW_SCORE_PASSWORD,
                acknowledged_weak=True,
            )

        refreshed = await temp_db.get_user_by_id(user.id)
        assert refreshed.verify_password(LOW_SCORE_PASSWORD)

    asyncio.run(scenario())


def test_admin_creation_uses_the_same_password_policy(
    temp_db: Persistence,
):
    async def scenario():
        root = await _create_password_user(
            temp_db,
            email="password-policy-root@example.com",
            role="root",
        )
        root_session = await temp_db.create_session(root.id)
        context = AdminMutationContext(auth_token=root_session.id)

        with pytest.raises(ValueError, match="acknowledge"):
            await temp_db.admin_create_user(
                email="rejected-admin-created@example.com",
                password="!!!!!!!!!!!!!!!",
                role="user",
                admin_context=context,
            )
        with pytest.raises(KeyError):
            await temp_db.get_user_by_email("rejected-admin-created@example.com")

        created = await temp_db.admin_create_user(
            email="low-score-admin-created@example.com",
            password=LOW_SCORE_PASSWORD,
            role="user",
            admin_context=context,
            acknowledged_weak=True,
        )
        assert created.verify_password(LOW_SCORE_PASSWORD)

    asyncio.run(scenario())


def test_signup_wiring_requests_acknowledgement_for_warned_password(
    temp_db: Persistence,
):
    class PersistenceSession:
        def __getitem__(self, key):
            if key is Persistence:
                return temp_db
            raise KeyError(key)

    form = SimpleNamespace(
        session=PersistenceSession(),
        email="rejected-signup@example.com",
        password=SHORT_PASSWORD,
        confirm_password=SHORT_PASSWORD,
        referral_code="",
        banner_style="danger",
        error_message="",
        passwords_valid=False,
        is_email_valid=False,
        acknowledge_weak_password=False,
        password_policy_error_visible=False,
    )
    asyncio.run(SignUpForm.on_sign_up_pressed(form))

    assert "acknowledge" in form.error_message
    assert temp_db.get_user_count() == 0


def test_reset_wiring_requests_acknowledgement_for_warned_password():
    form = SimpleNamespace(
        email="rejected-reset@example.com",
        reset_token="ValidResetToken123",
        new_password=SHORT_PASSWORD,
        confirm_password=SHORT_PASSWORD,
        banner_style="danger",
        error_message="",
        acknowledge_weak_password=False,
        password_policy_error_visible=False,
    )

    def set_banner(style: str, message: str) -> None:
        form.banner_style = style
        form.error_message = message

    form._set_banner = set_banner
    asyncio.run(ResetPasswordForm._update_password(form))

    assert form.banner_style == "danger"
    assert "acknowledge" in form.error_message
