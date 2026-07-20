import asyncio
from pathlib import Path

import pyotp
import pytest

from app.data_models import AppUser, UserSession
from app.persistence import Persistence, TwoFactorStateConflict
from app.persistence_social import (
    OAUTH_MFA_DISABLE_PURPOSE,
    OAUTH_MFA_ENABLE_PURPOSE,
    OAUTH_RECOVERY_CODES_PURPOSE,
)


@pytest.fixture
def temp_db(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "google-mfa-lifecycle.db")
    try:
        yield persistence
    finally:
        persistence.close()


async def _create_google_user_with_session(
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
    assert user.password_hash is None
    await persistence._create_user_unchecked(user)
    user = await persistence.get_user_by_id(user.id)
    assert user.password_hash is None
    return user, await persistence.create_session(user.id)


async def _create_approval(
    persistence: Persistence,
    user: AppUser,
    user_session: UserSession,
    purpose: str,
) -> str:
    challenge = await persistence.create_oauth_reauth_challenge(
        user_id=user.id,
        provider="google",
        purpose=purpose,
        auth_token=user_session.id,
    )
    return await persistence.exchange_oauth_reauth_challenge(
        challenge_token=challenge,
        provider="google",
        purpose=purpose,
        provider_user_id=str(user.auth_provider_id),
    )


def _handoff_exists(persistence: Persistence, token: str) -> bool:
    return bool(
        persistence.conn.execute(
            "SELECT 1 FROM oauth_login_handoffs WHERE token_hash = ?",
            (persistence._hash_one_time_token(token),),
        ).fetchone()
    )


def _unused_recovery_codes(persistence: Persistence, user_id) -> int:
    return int(
        persistence.conn.execute(
            """
            SELECT COUNT(*)
            FROM two_factor_recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            """,
            (str(user_id),),
        ).fetchone()[0]
    )


def test_google_mfa_approval_preflight_is_non_consuming_and_transaction_owned(
    temp_db: Persistence,
):
    async def scenario():
        user, user_session = await _create_google_user_with_session(
            temp_db,
            "google-preflight@example.com",
            provider_user_id="google-preflight-sub",
        )
        approval = await _create_approval(
            temp_db,
            user,
            user_session,
            OAUTH_MFA_ENABLE_PURPOSE,
        )
        token_hash = temp_db._hash_one_time_token(approval)
        before = temp_db.conn.execute(
            """
            SELECT user_id, provider, created_at, valid_until, consumed_at
            FROM oauth_login_handoffs
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()

        for _ in range(2):
            temp_db.validate_oauth_reauth_approval(
                approval_token=approval,
                user_id=user.id,
                provider="google",
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                auth_token=user_session.id,
            )
            assert temp_db.conn.in_transaction is False
            assert temp_db.conn.execute(
                """
                SELECT user_id, provider, created_at, valid_until, consumed_at
                FROM oauth_login_handoffs
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone() == before

        temp_db.conn.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            ("caller-pending", str(user.id)),
        )
        with pytest.raises(RuntimeError, match="existing transaction"):
            temp_db.validate_oauth_reauth_approval(
                approval_token=approval,
                user_id=user.id,
                provider="google",
                purpose=OAUTH_MFA_ENABLE_PURPOSE,
                auth_token=user_session.id,
            )
        assert temp_db.conn.in_transaction is True
        assert _handoff_exists(temp_db, approval)
        temp_db.conn.rollback()

        secret = pyotp.random_base32()
        codes = temp_db.enroll_two_factor_after_oauth_approval(
            user_id=user.id,
            auth_token=user_session.id,
            oauth_approval_token=approval,
            candidate_secret=secret,
            verification_code=pyotp.TOTP(secret).now(),
        )
        assert len(codes) == 10
        assert not _handoff_exists(temp_db, approval)

    asyncio.run(scenario())


def test_google_only_user_enrolls_totp_without_application_password(
    temp_db: Persistence,
):
    async def scenario():
        user, user_session = await _create_google_user_with_session(
            temp_db,
            "google-enroll@example.com",
            provider_user_id="google-enroll-sub",
        )
        approval = await _create_approval(
            temp_db,
            user,
            user_session,
            OAUTH_MFA_ENABLE_PURPOSE,
        )
        secret = pyotp.random_base32()
        valid_code = pyotp.TOTP(secret).now()
        invalid_code = f"{(int(valid_code) + 1) % 1_000_000:06d}"

        with pytest.raises(ValueError):
            temp_db.enroll_two_factor_after_oauth_approval(
                user_id=user.id,
                auth_token=user_session.id,
                oauth_approval_token=approval,
                candidate_secret=secret,
                verification_code=invalid_code,
            )
        assert _handoff_exists(temp_db, approval)
        assert not (await temp_db.get_user_by_id(user.id)).two_factor_enabled

        codes = temp_db.enroll_two_factor_after_oauth_approval(
            user_id=user.id,
            auth_token=user_session.id,
            oauth_approval_token=approval,
            candidate_secret=secret,
            verification_code=valid_code,
        )

        assert len(codes) == 10
        assert (await temp_db.get_user_by_id(user.id)).two_factor_secret == secret
        assert not _handoff_exists(temp_db, approval)

    asyncio.run(scenario())


def test_google_only_user_disables_totp_with_google_approval_and_recovery_code(
    temp_db: Persistence,
):
    async def scenario():
        user, user_session = await _create_google_user_with_session(
            temp_db,
            "google-disable@example.com",
            provider_user_id="google-disable-sub",
        )
        secret = pyotp.random_base32()
        recovery_code = temp_db.enroll_two_factor(user.id, secret, count=1)[0]
        approval = await _create_approval(
            temp_db,
            user,
            user_session,
            OAUTH_MFA_DISABLE_PURPOSE,
        )

        assert temp_db.disable_two_factor_after_oauth_approval(
            user_id=user.id,
            auth_token=user_session.id,
            oauth_approval_token=approval,
            two_factor_code=recovery_code,
            expected_secret=secret,
        )
        assert not (await temp_db.get_user_by_id(user.id)).two_factor_enabled
        assert _unused_recovery_codes(temp_db, user.id) == 0
        assert not _handoff_exists(temp_db, approval)

    asyncio.run(scenario())


def test_google_recovery_code_regeneration_is_atomic_and_approval_is_single_use(
    temp_db: Persistence,
):
    async def scenario():
        user, user_session = await _create_google_user_with_session(
            temp_db,
            "google-recovery@example.com",
            provider_user_id="google-recovery-sub",
        )
        secret = pyotp.random_base32()
        old_code = temp_db.enroll_two_factor(user.id, secret, count=1)[0]
        approval = await _create_approval(
            temp_db,
            user,
            user_session,
            OAUTH_RECOVERY_CODES_PURPOSE,
        )

        with pytest.raises(TwoFactorStateConflict):
            temp_db.generate_recovery_codes_after_oauth_approval(
                user_id=user.id,
                auth_token=user_session.id,
                oauth_approval_token=approval,
                two_factor_code=old_code,
                expected_secret=pyotp.random_base32(),
            )
        assert _handoff_exists(temp_db, approval)
        assert _unused_recovery_codes(temp_db, user.id) == 1

        new_codes = temp_db.generate_recovery_codes_after_oauth_approval(
            user_id=user.id,
            auth_token=user_session.id,
            oauth_approval_token=approval,
            two_factor_code=old_code,
            expected_secret=secret,
        )
        assert len(new_codes) == 10
        assert not _handoff_exists(temp_db, approval)

        with pytest.raises(KeyError):
            temp_db.generate_recovery_codes_after_oauth_approval(
                user_id=user.id,
                auth_token=user_session.id,
                oauth_approval_token=approval,
                two_factor_code=pyotp.TOTP(secret).now(),
                expected_secret=secret,
            )
        assert _unused_recovery_codes(temp_db, user.id) == 10

    asyncio.run(scenario())


def test_google_mfa_approval_is_session_and_purpose_bound(
    temp_db: Persistence,
):
    async def scenario():
        user, bound_session = await _create_google_user_with_session(
            temp_db,
            "google-bound@example.com",
            provider_user_id="google-bound-sub",
        )
        other_session = await temp_db.create_session(user.id)
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=1)
        wrong_purpose_approval = await _create_approval(
            temp_db,
            user,
            bound_session,
            OAUTH_MFA_ENABLE_PURPOSE,
        )

        with pytest.raises(KeyError):
            temp_db.disable_two_factor_after_oauth_approval(
                user_id=user.id,
                auth_token=bound_session.id,
                oauth_approval_token=wrong_purpose_approval,
                two_factor_code=pyotp.TOTP(secret).now(),
                expected_secret=secret,
            )
        assert _handoff_exists(temp_db, wrong_purpose_approval)

        approval = await _create_approval(
            temp_db,
            user,
            bound_session,
            OAUTH_MFA_DISABLE_PURPOSE,
        )
        with pytest.raises(KeyError):
            temp_db.disable_two_factor_after_oauth_approval(
                user_id=user.id,
                auth_token=other_session.id,
                oauth_approval_token=approval,
                two_factor_code=pyotp.TOTP(secret).now(),
                expected_secret=secret,
            )
        assert _handoff_exists(temp_db, approval)
        assert (await temp_db.get_user_by_id(user.id)).two_factor_enabled

    asyncio.run(scenario())


def test_expired_google_mfa_approval_cannot_mutate_factor(temp_db: Persistence):
    async def scenario():
        user, user_session = await _create_google_user_with_session(
            temp_db,
            "google-expired@example.com",
            provider_user_id="google-expired-sub",
        )
        secret = pyotp.random_base32()
        temp_db.enroll_two_factor(user.id, secret, count=1)
        approval = await _create_approval(
            temp_db,
            user,
            user_session,
            OAUTH_MFA_DISABLE_PURPOSE,
        )
        temp_db.conn.execute(
            "UPDATE oauth_login_handoffs SET valid_until = 0 WHERE token_hash = ?",
            (temp_db._hash_one_time_token(approval),),
        )
        temp_db.conn.commit()

        with pytest.raises(KeyError):
            temp_db.disable_two_factor_after_oauth_approval(
                user_id=user.id,
                auth_token=user_session.id,
                oauth_approval_token=approval,
                two_factor_code=pyotp.TOTP(secret).now(),
                expected_secret=secret,
            )
        assert (await temp_db.get_user_by_id(user.id)).two_factor_enabled

    asyncio.run(scenario())
