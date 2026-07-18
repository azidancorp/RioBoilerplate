import asyncio
import time
from collections import defaultdict
from pathlib import Path

import pyotp
import pytest

from app.config import config
from app.data_models import AppUser, UserSession, UserSettings
from app.pages.app_page.settings import Settings
from app.persistence import Persistence
from app.rio_cookie_security import browser_binding_digest


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "oauth-account-deletion.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_social_user_with_session(
    persistence: Persistence,
    email: str,
    *,
    provider_user_id: str,
) -> tuple[AppUser, UserSession]:
    user = AppUser.create_social_user(
        email=email,
        provider="google",
        provider_user_id=provider_user_id,
        is_verified=True,
    )
    await persistence._create_user_unchecked(user)
    user = await persistence.get_user_by_id(user.id)
    return user, await persistence.create_session(user.id)


async def _create_deletion_approval(
    persistence: Persistence,
    user: AppUser,
    user_session: UserSession,
) -> str:
    challenge = await persistence.create_oauth_account_deletion_challenge(
        user_id=user.id,
        provider="google",
        auth_token=user_session.id,
    )
    return await persistence.exchange_oauth_account_deletion_challenge(
        challenge_token=challenge,
        provider="google",
        provider_user_id=str(user.auth_provider_id),
    )


def _handoff_exists(persistence: Persistence, token: str) -> bool:
    return bool(
        persistence.conn.execute(
            "SELECT 1 FROM oauth_login_handoffs WHERE token_hash = ?",
            (persistence._hash_one_time_token(token),),
        ).fetchone()
    )


def _pending_login_exists(persistence: Persistence, binding_digest: str) -> bool:
    return bool(
        persistence.conn.execute(
            "SELECT 1 FROM oauth_pending_logins WHERE binding_digest = ?",
            (binding_digest,),
        ).fetchone()
    )


def test_oauth_deletion_proof_is_purpose_user_and_session_bound(
    temp_db: Persistence,
):
    async def scenario():
        user, bound_session = await _create_social_user_with_session(
            temp_db,
            "purpose-bound-delete@example.com",
            provider_user_id="delete-purpose-sub",
        )
        other_session = await temp_db.create_session(user.id)
        challenge = await temp_db.create_oauth_account_deletion_challenge(
            user_id=user.id,
            provider="google",
            auth_token=bound_session.id,
        )

        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(
                browser_binding_digest(challenge)
            )
        assert _handoff_exists(temp_db, challenge)

        with pytest.raises(KeyError):
            await temp_db.exchange_oauth_account_deletion_challenge(
                challenge_token=challenge,
                provider="google",
                provider_user_id="different-google-sub",
            )
        assert _handoff_exists(temp_db, challenge)

        approval = await temp_db.exchange_oauth_account_deletion_challenge(
            challenge_token=challenge,
            provider="google",
            provider_user_id="delete-purpose-sub",
        )
        assert not _handoff_exists(temp_db, challenge)
        assert _handoff_exists(temp_db, approval)

        with pytest.raises(KeyError):
            await temp_db.consume_oauth_pending_login(
                browser_binding_digest(approval)
            )
        assert await temp_db.delete_user(
            user.id,
            password=None,
            auth_token=other_session.id,
            oauth_reauth_token=approval,
        ) is False
        assert _handoff_exists(temp_db, approval)

        pending_login_digest = "a" * 64
        await temp_db.create_oauth_pending_login(
            binding_digest=pending_login_digest,
            user_id=user.id,
            provider="google",
        )
        assert await temp_db.delete_user(
            user.id,
            password=None,
            auth_token=bound_session.id,
            oauth_reauth_token=pending_login_digest,
        ) is False
        assert _pending_login_exists(temp_db, pending_login_digest)

        assert await temp_db.delete_user(
            user.id,
            password=None,
            auth_token=bound_session.id,
            oauth_reauth_token=approval,
        ) is True
        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(user.id)

    asyncio.run(scenario())


def test_oauth_deletion_rolls_back_approval_when_delete_fails(
    temp_db: Persistence,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        user, user_session = await _create_social_user_with_session(
            temp_db,
            "rollback-oauth-delete@example.com",
            provider_user_id="delete-rollback-sub",
        )
        recovery_code = temp_db.enroll_two_factor(
            user.id,
            pyotp.random_base32(),
            count=1,
        )[0]
        approval = await _create_deletion_approval(temp_db, user, user_session)
        original_record_admin_action = temp_db.record_admin_action

        def fail_audit(**kwargs) -> None:
            raise RuntimeError("forced delete audit failure")

        monkeypatch.setattr(temp_db, "record_admin_action", fail_audit)
        with pytest.raises(RuntimeError, match="forced delete audit failure"):
            await temp_db.delete_user(
                user.id,
                password=None,
                two_factor_code=recovery_code,
                auth_token=user_session.id,
                oauth_reauth_token=approval,
            )

        assert (await temp_db.get_user_by_id(user.id)).id == user.id
        assert _handoff_exists(temp_db, approval)
        unused_recovery_codes = temp_db.conn.execute(
            """
            SELECT COUNT(*)
            FROM two_factor_recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            """,
            (str(user.id),),
        ).fetchone()[0]
        assert unused_recovery_codes == 1

        monkeypatch.setattr(
            temp_db,
            "record_admin_action",
            original_record_admin_action,
        )
        assert await temp_db.delete_user(
            user.id,
            password=None,
            two_factor_code=recovery_code,
            auth_token=user_session.id,
            oauth_reauth_token=approval,
        ) is True

    asyncio.run(scenario())


@pytest.mark.parametrize("session_state", ["revoked", "expired", "absolute"])
def test_oauth_deletion_challenge_rejects_a_session_that_stopped_being_live(
    temp_db: Persistence,
    session_state: str,
    monkeypatch: pytest.MonkeyPatch,
):
    async def scenario():
        user, user_session = await _create_social_user_with_session(
            temp_db,
            f"{session_state}-oauth-delete@example.com",
            provider_user_id=f"{session_state}-delete-sub",
        )
        challenge = await temp_db.create_oauth_account_deletion_challenge(
            user_id=user.id,
            provider="google",
            auth_token=user_session.id,
        )
        session_hash = temp_db._hash_one_time_token(user_session.id)
        if session_state == "revoked":
            temp_db.conn.execute(
                "DELETE FROM user_sessions WHERE id = ?",
                (session_hash,),
            )
        elif session_state == "expired":
            temp_db.conn.execute(
                "UPDATE user_sessions SET valid_until = 0 WHERE id = ?",
                (session_hash,),
            )
        else:
            monkeypatch.setattr(config, "SESSION_ABSOLUTE_MAX_DAYS", 30)
            old_created_at = time.time() - (
                (config.SESSION_ABSOLUTE_MAX_DAYS + 1) * 24 * 60 * 60
            )
            temp_db.conn.execute(
                "UPDATE user_sessions SET created_at = ? WHERE id = ?",
                (old_created_at, session_hash),
            )
        temp_db.conn.commit()

        with pytest.raises(KeyError):
            await temp_db.exchange_oauth_account_deletion_challenge(
                challenge_token=challenge,
                provider="google",
                provider_user_id=str(user.auth_provider_id),
            )
        assert _handoff_exists(temp_db, challenge)
        assert (await temp_db.get_user_by_id(user.id)).id == user.id

    asyncio.run(scenario())


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(
        self,
        persistence: Persistence,
        user_session: UserSession,
        user: AppUser,
    ):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=user_session.id),
            UserSession: user_session,
            AppUser: user,
        }
        self.client_ip = "198.51.100.91"
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self.running_as_website = True
        self.navigation_target: str | None = None
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        return self._attachments[key]

    def attach(self, value) -> None:
        self._attachments[type(value)] = value

    def detach(self, key) -> None:
        del self._attachments[key]

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url

    def _register_dirty_component(self, component) -> None:
        pass


def _mount_settings(session: _FakeSession, **attributes) -> Settings:
    component = object.__new__(Settings)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component.delete_account_password = ""
    component.delete_account_2fa = ""
    component.delete_account_confirmation = ""
    component.delete_account_error = ""
    component.delete_account_oauth_token = ""
    component.delete_account_oauth_status = ""
    for key, value in attributes.items():
        setattr(component, key, value)
    return component


def test_settings_oauth_deletion_requires_provider_proof_not_password(
    temp_db: Persistence,
):
    async def scenario():
        user, user_session = await _create_social_user_with_session(
            temp_db,
            "settings-oauth-delete@example.com",
            provider_user_id="settings-delete-sub",
        )
        rio_session = _FakeSession(temp_db, user_session, user)
        page = _mount_settings(
            rio_session,
            delete_account_confirmation="DELETE MY ACCOUNT",
            delete_account_password="not-an-app-password",
        )

        await Settings._on_delete_account_pressed(page)
        assert (await temp_db.get_user_by_id(user.id)).id == user.id
        assert "Verify with Google again" in page.delete_account_error
        assert "password" not in page.delete_account_error.lower()

        page.delete_account_oauth_token = await _create_deletion_approval(
            temp_db,
            user,
            user_session,
        )
        page.delete_account_confirmation = "DELETE MY ACCOUNT"
        await Settings._on_delete_account_pressed(page)

        with pytest.raises(KeyError):
            await temp_db.get_user_by_id(user.id)
        assert rio_session[UserSettings].auth_token == ""
        assert rio_session.navigation_target == "/"

    asyncio.run(scenario())
