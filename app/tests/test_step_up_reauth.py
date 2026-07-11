"""Tests for per-action step-up re-auth gating of sensitive admin actions.

Covers the ``verify_step_up_credentials`` helper, the admin role-change
prompt + dialog flow (which always requires the acting admin's own
credentials), the step-up rate limit, and the per-action flows for admin
deletion and currency updates. Admin lifecycle tests cover privileged creation,
account-status changes, password-reset issuance, and email changes.
"""

import asyncio
from pathlib import Path

import pyotp
import pytest

from app.config import config
from app.pages.app_page.admin import AdminPage
from app.persistence import Persistence
from app.rate_limits import rate_limit_key, sensitive_action_policy
from app.session_validation import StepUpResult, verify_step_up_credentials

# Reuse the fake-session / mounting helpers (kept in sync with AdminPage state).
from tests.test_admin_user_lifecycle import (
    PASSWORD,
    _FakeSession,
    _admin_action_count,
    _admin_context,
    _create_oauth_root_session,
    _create_root_session,
    _create_user,
    _mount_admin,
    _race_admin_authorization,
)


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "step-up-reauth.db")
    try:
        yield persistence
    finally:
        persistence.close()


def _totp_now(secret: str) -> str:
    return pyotp.TOTP(secret).now()


# ---------------------------------------------------------------------------
# Step-up verification helper
# ---------------------------------------------------------------------------


def test_verify_step_up_credentials_password_only(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password=PASSWORD,
            two_factor_code=None,
        )

        assert result.ok is True
        assert result.used_recovery_code is False

    asyncio.run(scenario())


def test_verify_step_up_credentials_wrong_password(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password="not-the-password",
            two_factor_code=None,
        )

        assert result.ok is False
        assert result.error_message == "Current password is incorrect"

    asyncio.run(scenario())


def test_verify_step_up_credentials_rejects_session_user_mismatch(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        other = await _create_user(temp_db, "other-stepup@example.com")

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            other,
            password=PASSWORD,
            two_factor_code=None,
        )

        assert result.ok is False
        assert result.error_message == "Your session has expired. Please log in again."

    asyncio.run(scenario())


def test_verify_step_up_credentials_with_2fa(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        # Reload so two_factor_enabled reflects the secret just set.
        root = await temp_db.get_user_by_id(root.id)

        # Missing code.
        missing = await verify_step_up_credentials(
            temp_db, root_session, root, password=PASSWORD, two_factor_code=None
        )
        assert missing.ok is False
        assert missing.error_message == "2FA code is required"

        # Wrong code.
        wrong = await verify_step_up_credentials(
            temp_db, root_session, root, password=PASSWORD, two_factor_code="000000"
        )
        assert wrong.ok is False
        assert wrong.error_message == "Invalid 2FA or recovery code."

        # Correct code (retry briefly to avoid the 30s TOTP boundary flake).
        ok_result = None
        for _ in range(3):
            ok_result = await verify_step_up_credentials(
                temp_db,
                root_session,
                root,
                password=PASSWORD,
                two_factor_code=_totp_now(secret),
            )
            if ok_result.ok:
                break
        assert ok_result is not None and ok_result.ok is True

    asyncio.run(scenario())


def test_verify_step_up_credentials_consumes_recovery_code(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        codes = temp_db.generate_recovery_codes(root.id)
        # Reload so two_factor_enabled reflects the secret just set.
        root = await temp_db.get_user_by_id(root.id)

        result = await verify_step_up_credentials(
            temp_db, root_session, root, password=PASSWORD, two_factor_code=codes[0]
        )
        assert result.ok is True
        assert result.used_recovery_code is True

        # The recovery code is single-use, mirroring the settings password-change flow.
        reuse = await verify_step_up_credentials(
            temp_db, root_session, root, password=PASSWORD, two_factor_code=codes[0]
        )
        assert reuse.ok is False

    asyncio.run(scenario())


def test_verify_step_up_credentials_rejects_removed_oauth_factor(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_oauth_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        root = await temp_db.get_user_by_id(root.id)
        assert root.two_factor_enabled is True

        assert temp_db.disable_two_factor(root.id, expected_secret=secret) is True
        assert (await temp_db.get_user_by_id(root.id)).two_factor_enabled is False

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password="",
            two_factor_code=None,
        )

        assert result.ok is False
        assert result.error_message == (
            "Two-factor authentication changed. Please try again."
        )

    asyncio.run(scenario())


def test_verify_step_up_credentials_rejects_new_password_factor(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        assert root.two_factor_enabled is False

        temp_db.set_2fa_secret(root.id, pyotp.random_base32())
        assert (await temp_db.get_user_by_id(root.id)).two_factor_enabled is True

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password=PASSWORD,
            two_factor_code=None,
        )

        assert result.ok is False
        assert result.error_message == (
            "Two-factor authentication changed. Please try again."
        )

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Admin handler prompt + dialog flow
# ---------------------------------------------------------------------------


def test_role_change_always_prompts_for_step_up(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "target@example.com")
        original_role = target.role

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        await AdminPage._on_change_role_pressed(page)

        # The step-up dialog is shown and the pending action is stashed...
        assert page.step_up_visible is True
        assert page.step_up_pending_identifier == target.email
        assert page.step_up_pending_user_id == str(target.id)
        assert page.step_up_pending_new_role == "admin"
        # ...and crucially, no mutation happened.
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == original_role

    asyncio.run(scenario())


def test_role_change_stays_pinned_to_target_id_when_identifier_is_reused(
    temp_db: Persistence,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        original = await _create_user(temp_db, "role-original@example.com")
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=original.email,
            change_role_new_role="admin",
        )

        await AdminPage._on_change_role_pressed(page)
        assert page.step_up_pending_user_id == str(original.id)

        await temp_db.admin_update_user_profile(
            original.id,
            admin_context=_admin_context(root_session),
            email="role-renamed@example.com",
            expected_email=original.email,
        )
        replacement = await _create_user(temp_db, original.email)

        page.step_up_password = PASSWORD
        await AdminPage._on_step_up_submit(page)

        assert (await temp_db.get_user_by_id(original.id)).role == "admin"
        assert (await temp_db.get_user_by_id(replacement.id)).role == "user"
        assert page.change_role_error == ""

    asyncio.run(scenario())


def test_role_step_up_verifier_exception_clears_secrets_without_mutating(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "role-verifier-error@example.com")
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )
        await AdminPage._on_change_role_pressed(page)
        page.step_up_password = PASSWORD
        page.step_up_2fa = "123456"

        async def fail_verification(*args, **kwargs):
            raise RuntimeError("forced verifier failure")

        monkeypatch.setattr(
            AdminPage,
            "_verify_actor_step_up",
            fail_verification,
        )

        await AdminPage._on_step_up_submit(page)

        assert page.step_up_password == ""
        assert page.step_up_2fa == ""
        assert page.step_up_error == (
            "Could not verify your credentials. Please try again."
        )
        assert page.step_up_visible is True
        assert page.step_up_pending_user_id == str(target.id)
        assert (await temp_db.get_user_by_id(target.id)).role == target.role

    asyncio.run(scenario())


def test_role_change_recovery_warning_covers_success_and_mutation_failure(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    expected_warning = (
        "A recovery code was used. Generate a new set to stay protected."
    )

    async def use_recovery_code(*args, **kwargs):
        return StepUpResult(ok=True, used_recovery_code=True)

    monkeypatch.setattr(
        AdminPage,
        "_verify_actor_step_up",
        use_recovery_code,
    )

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        success_target = await _create_user(
            temp_db,
            "role-recovery-success@example.com",
        )
        success_page = _mount_admin(
            session,
            change_role_identifier=success_target.email,
            change_role_new_role="admin",
        )
        await AdminPage._on_change_role_pressed(success_page)
        await AdminPage._on_step_up_submit(success_page)

        assert (await temp_db.get_user_by_id(success_target.id)).role == "admin"
        assert success_page.change_role_error == expected_warning
        assert success_page.change_role_error.count(expected_warning) == 1

        failure_target = await _create_user(
            temp_db,
            "role-recovery-failure@example.com",
        )
        failure_page = _mount_admin(
            session,
            change_role_identifier=failure_target.email,
            change_role_new_role="admin",
        )
        await AdminPage._on_change_role_pressed(failure_page)

        async def reject_role_update(*args, **kwargs):
            raise PermissionError("Administrator authorization changed.")

        monkeypatch.setattr(
            temp_db,
            "admin_update_user_role",
            reject_role_update,
        )
        await AdminPage._on_step_up_submit(failure_page)

        assert (await temp_db.get_user_by_id(failure_target.id)).role == "user"
        assert failure_page.change_role_error == (
            f"Administrator authorization changed. {expected_warning}"
        )
        assert failure_page.change_role_error.count(expected_warning) == 1

    asyncio.run(scenario())


def test_role_change_reprompts_after_previous_success(temp_db: Persistence):
    """A second role change re-prompts even right after one succeeded."""

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        first = await _create_user(temp_db, "first@example.com")
        second = await _create_user(temp_db, "second@example.com")

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=first.email,
            change_role_new_role="admin",
        )

        # Complete a full step-up + role change for the first target.
        await AdminPage._on_change_role_pressed(page)
        page.step_up_password = PASSWORD
        await AdminPage._on_step_up_submit(page)
        refreshed_first = await temp_db.get_user_by_id(first.id)
        assert refreshed_first.role == "admin"

        # The very next role change must prompt again.
        page.change_role_identifier = second.email
        page.change_role_new_role = "admin"
        await AdminPage._on_change_role_pressed(page)

        assert page.step_up_visible is True
        refreshed_second = await temp_db.get_user_by_id(second.id)
        assert refreshed_second.role == second.role

    asyncio.run(scenario())


def test_full_step_up_dialog_flow_completes_role_change(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "flow@example.com")

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            change_role_identifier=target.email,
            change_role_new_role="admin",
        )

        # First attempt is gated and reveals the dialog.
        await AdminPage._on_change_role_pressed(page)
        assert page.step_up_visible is True

        # Supply credentials and submit the dialog.
        page.step_up_password = PASSWORD
        await AdminPage._on_step_up_submit(page)

        assert page.step_up_visible is False
        assert page.change_role_identifier == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.role == "admin"

    asyncio.run(scenario())


def test_step_up_attempts_are_rate_limited(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS", 2)

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        targets = [
            await _create_user(temp_db, "ratelimit-1@example.com"),
            await _create_user(temp_db, "ratelimit-2@example.com"),
            await _create_user(temp_db, "ratelimit-3@example.com"),
        ]

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            step_up_visible=True,
            step_up_pending_identifier=targets[0].email,
            step_up_pending_user_id=str(targets[0].id),
            step_up_pending_new_role="admin",
            step_up_password="wrong-password",
        )

        await AdminPage._on_step_up_submit(page)
        assert page.step_up_error == "Current password is incorrect"

        page.step_up_pending_identifier = targets[1].email
        page.step_up_pending_user_id = str(targets[1].id)
        page.step_up_password = "wrong-password"
        await AdminPage._on_step_up_submit(page)
        assert page.step_up_error == "Current password is incorrect"

        # The third attempt is throttled by the actor-keyed admin_step_up scope.
        page.step_up_pending_identifier = targets[2].email
        page.step_up_pending_user_id = str(targets[2].id)
        page.step_up_password = "wrong-password"
        await AdminPage._on_step_up_submit(page)
        assert "Too many verification attempts" in page.step_up_error
        # The targets were never mutated.
        for target in targets:
            refreshed = await temp_db.get_user_by_id(target.id)
            assert refreshed.role == target.role

    asyncio.run(scenario())


def test_ui_step_up_uses_api_compatible_actor_rate_limit_key(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS", 2)

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(session, current_user=root)

        first = await AdminPage._verify_actor_step_up(
            page,
            temp_db,
            password="wrong-password",
            two_factor_code=None,
        )
        second = await AdminPage._verify_actor_step_up(
            page,
            temp_db,
            password="wrong-password",
            two_factor_code=None,
        )

        assert first.error_message == "Current password is incorrect"
        assert second.error_message == "Current password is incorrect"

        api_key_decision = temp_db.check_rate_limit(
            policy=sensitive_action_policy("admin_step_up"),
            key=rate_limit_key("admin_step_up", root.id),
        )
        assert api_key_decision.allowed is False

    asyncio.run(scenario())


def test_role_change_limit_blocks_before_consuming_recovery_code(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "RATE_LIMIT_SENSITIVE_ACTION_ATTEMPTS", 1)

    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        secret = pyotp.random_base32()
        temp_db.set_2fa_secret(root.id, secret)
        recovery_code = temp_db.generate_recovery_codes(root.id, count=1)[0]
        root = await temp_db.get_user_by_id(root.id)
        target = await _create_user(temp_db, "role-limit-recovery@example.com")

        temp_db.check_rate_limit(
            policy=sensitive_action_policy("admin_change_role"),
            key=rate_limit_key("admin_change_role", f"{root.id}:{target.id}"),
        )

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            step_up_visible=True,
            step_up_pending_identifier=target.email,
            step_up_pending_user_id=str(target.id),
            step_up_pending_new_role="admin",
            step_up_password=PASSWORD,
            step_up_2fa=recovery_code,
        )

        await AdminPage._on_step_up_submit(page)

        assert "Too many role-change attempts" in page.step_up_error
        refreshed_target = await temp_db.get_user_by_id(target.id)
        assert refreshed_target.role == target.role

        result = await verify_step_up_credentials(
            temp_db,
            root_session,
            root,
            password=PASSWORD,
            two_factor_code=recovery_code,
        )
        assert result.ok is True
        assert result.used_recovery_code is True

    asyncio.run(scenario())


def test_admin_delete_uses_actor_step_up_and_bypasses_target_2fa(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "delete-2fa-target@example.com")
        temp_db.set_2fa_secret(target.id, pyotp.random_base32())

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            delete_user_identifier=target.email,
            delete_user_confirmation=f"DELETE USER {target.email}",
            delete_user_step_up_password=PASSWORD,
        )

        await AdminPage._on_delete_user_pressed(page)

        assert page.delete_user_error == ""
        assert target.email in page.delete_user_success
        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(target.id)

    asyncio.run(scenario())


@pytest.mark.parametrize("authorization_change", ["demote", "revoke"])
def test_admin_delete_rejects_authorization_lost_during_step_up(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
    authorization_change: str,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "delete-race-target@example.com")
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            delete_user_identifier=target.email,
            delete_user_confirmation=f"DELETE USER {target.email}",
            delete_user_step_up_password=PASSWORD,
            delete_user_step_up_2fa="should-be-cleared",
        )

        async def lose_authorization_during_step_up(*args, **kwargs):
            _race_admin_authorization(
                temp_db,
                actor_user_id=root.id,
                authorization_change=authorization_change,
            )
            return StepUpResult(ok=True)

        monkeypatch.setattr(
            AdminPage,
            "_verify_actor_step_up",
            lose_authorization_during_step_up,
        )

        await AdminPage._on_delete_user_pressed(page)

        assert (await temp_db.get_user_by_id(target.id)).email == target.email
        assert _admin_action_count(
            temp_db,
            action="user_delete",
            target_user_id=target.id,
        ) == 0
        assert page.delete_user_success == ""
        assert page.delete_user_step_up_password == ""
        assert page.delete_user_step_up_2fa == ""
        assert session.navigation_target == "/"

    asyncio.run(scenario())


def test_currency_update_uses_actor_step_up(temp_db: Persistence):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "currency-stepup-target@example.com")

        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            currency_user_identifier=target.email,
            currency_amount="25",
            currency_reason="sudo test",
            currency_step_up_password=PASSWORD,
        )

        await AdminPage._on_currency_submit(page)

        assert page.currency_error == ""
        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.primary_currency_balance == target.primary_currency_balance + 25

    asyncio.run(scenario())


@pytest.mark.parametrize("authorization_change", ["demote", "revoke"])
def test_admin_currency_update_rejects_authorization_lost_during_step_up(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
    authorization_change: str,
):
    async def scenario():
        root, root_session = await _create_root_session(temp_db)
        target = await _create_user(temp_db, "currency-race-target@example.com")
        ledger_count_before = temp_db.conn.execute(
            "SELECT COUNT(*) FROM user_currency_ledger WHERE user_id = ?",
            (str(target.id),),
        ).fetchone()[0]
        session = _FakeSession(temp_db, root_session, root)
        page = _mount_admin(
            session,
            currency_user_identifier=target.email,
            currency_amount="25",
            currency_reason="must not land",
            currency_step_up_password=PASSWORD,
            currency_step_up_2fa="should-be-cleared",
        )

        async def lose_authorization_during_step_up(*args, **kwargs):
            _race_admin_authorization(
                temp_db,
                actor_user_id=root.id,
                authorization_change=authorization_change,
            )
            return StepUpResult(ok=True)

        monkeypatch.setattr(
            AdminPage,
            "_verify_actor_step_up",
            lose_authorization_during_step_up,
        )

        await AdminPage._on_currency_submit(page)

        refreshed = await temp_db.get_user_by_id(target.id)
        assert refreshed.primary_currency_balance == target.primary_currency_balance
        ledger_count_after = temp_db.conn.execute(
            "SELECT COUNT(*) FROM user_currency_ledger WHERE user_id = ?",
            (str(target.id),),
        ).fetchone()[0]
        assert ledger_count_after == ledger_count_before
        assert _admin_action_count(
            temp_db,
            action="currency_adjust",
            target_user_id=target.id,
        ) == 0
        assert page.currency_success == ""
        assert page.currency_step_up_password == ""
        assert page.currency_step_up_2fa == ""
        assert session.navigation_target == "/"

    asyncio.run(scenario())
