import asyncio
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pyotp
import pytest
from pwdlib import PasswordHash

from app import passwords as password_utils
from app.data_models import AppUser, UserSettings
from app.pages.login import LoginForm
from app.persistence import Persistence


def test_password_service_hashes_and_verifies_argon2id():
    password_hash, password_salt, password_scheme = password_utils.hash_password("StrongPass!123")

    assert password_scheme == password_utils.HASH_SCHEME_ARGON2ID
    assert password_salt is None
    assert password_hash.startswith(b"$argon2id$")

    assert password_utils.verify_password(
        "StrongPass!123",
        password_hash,
        password_salt,
        password_scheme,
    ).ok
    assert not password_utils.verify_password(
        "WrongPass!123",
        password_hash,
        password_salt,
        password_scheme,
    ).ok


@pytest.mark.parametrize(
    "password",
    [
        "     ",
        "\x00" * 15,
        "\u200b" * 15,
        "x" * 1025,
    ],
)
def test_acknowledgeable_quality_warnings_are_technically_hashable(
    password: str,
):
    password_hash, password_salt, password_scheme = password_utils.hash_password(
        password
    )

    assert password_utils.verify_password(
        password,
        password_hash,
        password_salt,
        password_scheme,
    ).ok


def test_new_hashes_use_nfc_and_accept_canonically_equivalent_input():
    decomposed = "Cafe\u0301-Utilisateur!2026"
    composed = "Café-Utilisateur!2026"

    password_hash, password_salt, password_scheme = password_utils.hash_password(
        decomposed
    )

    decomposed_result = password_utils.verify_password(
        decomposed,
        password_hash,
        password_salt,
        password_scheme,
    )
    composed_result = password_utils.verify_password(
        composed,
        password_hash,
        password_salt,
        password_scheme,
    )
    assert decomposed_result.ok and not decomposed_result.needs_rehash
    assert composed_result.ok and not composed_result.needs_rehash


def test_pre_normalization_argon2_hash_has_compatible_rehash_path():
    decomposed = "Cafe\u0301-Utilisateur!2026"
    raw_legacy_hash = PasswordHash.recommended().hash(decomposed).encode("utf-8")

    result = password_utils.verify_password(
        decomposed,
        raw_legacy_hash,
        None,
        password_utils.HASH_SCHEME_ARGON2ID,
    )

    assert result.ok
    assert result.needs_rehash


def test_pre_normalization_pbkdf2_hash_has_compatible_rehash_path():
    decomposed = "Cafe\u0301-Utilisateur!2026"
    password_salt = b"pre-normalization-salt"
    raw_legacy_hash = password_utils.legacy_pbkdf2_password_hash(
        decomposed,
        password_salt,
    )

    result = password_utils.verify_password(
        decomposed,
        raw_legacy_hash,
        password_salt,
        password_utils.HASH_SCHEME_PBKDF2_SHA256,
    )

    assert result.ok
    assert result.needs_rehash


def test_password_service_verifies_legacy_pbkdf2_and_marks_for_rehash():
    password_salt = b"legacy-salt"
    password_hash = AppUser.get_password_hash("LegacyPass!123", password_salt)

    result = password_utils.verify_password(
        "LegacyPass!123",
        password_hash,
        password_salt,
        password_utils.HASH_SCHEME_PBKDF2_SHA256,
    )
    assert result.ok
    assert result.needs_rehash

    missing_scheme_result = password_utils.verify_password(
        "LegacyPass!123",
        password_hash,
        password_salt,
        None,
    )
    assert missing_scheme_result.ok
    assert missing_scheme_result.needs_rehash

    wrong_result = password_utils.verify_password(
        "WrongPass!123",
        password_hash,
        password_salt,
        password_utils.HASH_SCHEME_PBKDF2_SHA256,
    )
    assert not wrong_result.ok
    assert not wrong_result.needs_rehash


def test_fresh_database_has_user_auth_state_columns(tmp_path: Path):
    persistence = Persistence(db_path=tmp_path / "fresh.db")
    try:
        cursor = persistence._get_cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}
    finally:
        persistence.close()

    assert "password_scheme" in columns
    assert "is_active" in columns


def test_legacy_database_gets_user_auth_state_columns(tmp_path: Path):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                username TEXT,
                created_at REAL NOT NULL,
                password_hash BLOB,
                password_salt BLOB,
                auth_provider TEXT NOT NULL DEFAULT 'password',
                auth_provider_id TEXT,
                role TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                referral_code TEXT DEFAULT '',
                email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
                sms_notifications_enabled BOOLEAN NOT NULL DEFAULT 0,
                primary_currency_balance INTEGER NOT NULL DEFAULT 0,
                primary_currency_updated_at REAL NOT NULL DEFAULT 0
            )
            """
        )

    persistence = Persistence(db_path=db_path)
    try:
        cursor = persistence._get_cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}
    finally:
        persistence.close()

    assert "password_scheme" in columns
    assert "is_active" in columns


def test_legacy_database_row_maps_correctly_after_password_scheme_migration(tmp_path: Path):
    db_path = tmp_path / "legacy-row.db"
    user_id = uuid.uuid4()
    created_at = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
    updated_at = datetime(2026, 1, 3, 4, 5, tzinfo=timezone.utc)
    password_salt = b"legacy-row-salt"
    password_hash = AppUser.get_password_hash("LegacyPass!123", password_salt)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                username TEXT,
                created_at REAL NOT NULL,
                password_hash BLOB,
                password_salt BLOB,
                auth_provider TEXT NOT NULL DEFAULT 'password',
                auth_provider_id TEXT,
                role TEXT NOT NULL,
                is_verified BOOLEAN NOT NULL DEFAULT 0,
                two_factor_secret TEXT,
                referral_code TEXT DEFAULT '',
                email_notifications_enabled BOOLEAN NOT NULL DEFAULT 1,
                sms_notifications_enabled BOOLEAN NOT NULL DEFAULT 0,
                primary_currency_balance INTEGER NOT NULL DEFAULT 0,
                primary_currency_updated_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            INSERT INTO users (
                id, email, username, created_at, password_hash, password_salt,
                auth_provider, auth_provider_id, role, is_verified,
                two_factor_secret, referral_code, email_notifications_enabled,
                sms_notifications_enabled, primary_currency_balance,
                primary_currency_updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(user_id),
                "legacy-row@example.com",
                "legacyrow",
                created_at.timestamp(),
                password_hash,
                password_salt,
                "password",
                None,
                "admin",
                1,
                "ABCDEFGHIJKLMNOPQRSTUVWX23456789",
                "REF123",
                0,
                1,
                1234,
                updated_at.timestamp(),
            ),
        )

    async def scenario():
        persistence = Persistence(db_path=db_path)
        try:
            stored = await persistence.get_user_by_id(user_id)

            assert stored.email == "legacy-row@example.com"
            assert stored.username == "legacyrow"
            assert stored.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert stored.auth_provider == "password"
            assert stored.role == "admin"
            assert stored.is_verified is True
            assert stored.is_active is True
            assert stored.two_factor_secret == "ABCDEFGHIJKLMNOPQRSTUVWX23456789"
            assert stored.referral_code == "REF123"
            assert stored.email_notifications_enabled is False
            assert stored.sms_notifications_enabled is True
            assert stored.primary_currency_balance == 1234
            assert stored.primary_currency_updated_at == updated_at
            assert stored.verify_password("LegacyPass!123")
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_create_user_stores_argon2id_password(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "create.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="create@example.com",
                password="StrongPass!123",
            )
            await persistence._create_user_unchecked(user)
            stored = await persistence.get_user_by_id(user.id)

            assert stored.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert stored.password_salt is None
            assert stored.password_hash.startswith(b"$argon2id$")
            assert stored.verify_password("StrongPass!123")
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_non_password_provider_cannot_verify_or_upgrade(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "non-password.db")
        try:
            external_user = AppUser(
                id=uuid.uuid4(),
                email="external@example.com",
                username=None,
                created_at=datetime.now(timezone.utc),
                password_hash=None,
                password_salt=None,
                password_scheme=password_utils.HASH_SCHEME_ARGON2ID,
                auth_provider="oidc",
                auth_provider_id="provider-user-123",
                role="user",
                is_verified=True,
            )
            await persistence._create_user_unchecked(external_user)
            stored = await persistence.get_user_by_id(external_user.id)

            assert not stored.verify_password("Anything!123")

            try:
                await persistence.upgrade_user_password_hash(
                    stored.id,
                    "Anything!123",
                )
                upgraded = True
            except ValueError:
                upgraded = False

            refreshed = await persistence.get_user_by_id(stored.id)
            assert upgraded is False
            assert refreshed.auth_provider == "oidc"
            assert refreshed.password_hash is None
            assert refreshed.password_salt is None
            assert refreshed.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_update_password_stores_argon2id_and_invalidates_sessions(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "update.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="update@example.com",
                password="OldPass!123",
            )
            await persistence._create_user_unchecked(user)
            session = await persistence.create_session(user.id)

            await persistence.update_password(user.id, "NewVeryStrongPass!123")

            stored = await persistence.get_user_by_id(user.id)
            assert stored.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert stored.password_salt is None
            assert stored.verify_password("NewVeryStrongPass!123")
            assert not stored.verify_password("OldPass!123")

            with pytest.raises(KeyError):
                await persistence.get_session_by_auth_token(session.id)
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_reset_token_success_updates_password_consumes_token_and_invalidates_sessions(
    tmp_path: Path,
):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "reset-success.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="reset-success@example.com",
                password="OldPass!123",
            )
            await persistence._create_user_unchecked(user)
            session = await persistence.create_session(user.id)
            reset_token = await persistence.create_reset_token(user.id)

            consumed = await persistence.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                "NewVeryStrongPass!123",
            )

            stored = await persistence.get_user_by_id(user.id)
            assert consumed is True
            assert stored.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert stored.password_salt is None
            assert stored.verify_password("NewVeryStrongPass!123")
            assert not stored.verify_password("OldPass!123")

            assert await persistence.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                "AnotherPass!123",
            ) is False

            with pytest.raises(KeyError):
                await persistence.get_session_by_auth_token(session.id)
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_reset_token_success_with_mfa_updates_password_after_challenge(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "reset-success-mfa.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="reset-success-mfa@example.com",
                password="OldPass!123",
            )
            await persistence._create_user_unchecked(user)
            secret = pyotp.random_base32()
            persistence.set_2fa_secret(user.id, secret)
            reset_token = await persistence.create_reset_token(user.id)

            bad_result = persistence.verify_two_factor_challenge(user.id, "000000")
            assert not bad_result.ok
            stored_after_bad_mfa = await persistence.get_user_by_id(user.id)
            owner = await persistence.get_user_by_reset_token(reset_token.token)
            assert stored_after_bad_mfa.verify_password("OldPass!123")
            assert owner.id == user.id

            good_result = persistence.verify_two_factor_challenge(
                user.id,
                pyotp.TOTP(secret).now(),
            )
            assert good_result.ok
            consumed = await persistence.consume_reset_token_and_update_password(
                reset_token.token,
                user.id,
                "NewVeryStrongPass!123",
            )

            stored = await persistence.get_user_by_id(user.id)
            assert consumed is True
            assert stored.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert stored.password_salt is None
            assert stored.verify_password("NewVeryStrongPass!123")
            assert not stored.verify_password("OldPass!123")
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_reset_token_password_update_is_transactional_on_hash_failure(
    tmp_path: Path,
    monkeypatch,
):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "reset-transactional.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="reset-transactional@example.com",
                password="OldPass!123",
            )
            await persistence._create_user_unchecked(user)
            reset_token = await persistence.create_reset_token(user.id)

            def fail_hash(_password: str):
                raise RuntimeError("argon unavailable")

            monkeypatch.setattr(password_utils, "hash_password", fail_hash)

            try:
                await persistence.consume_reset_token_and_update_password(
                    reset_token.token,
                    user.id,
                    "NewVeryStrongPass!123",
                )
                failed = False
            except RuntimeError:
                failed = True

            stored = await persistence.get_user_by_id(user.id)
            assert failed
            assert stored.verify_password("OldPass!123")
            owner = await persistence.get_user_by_reset_token(reset_token.token)
            assert owner.id == user.id
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_legacy_pbkdf2_user_can_be_upgraded_after_successful_verification(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "upgrade.db")
        try:
            legacy_user = _legacy_user("legacy@example.com", "LegacyPass!123")
            await persistence._create_user_unchecked(legacy_user)

            stored_before = await persistence.get_user_by_id(legacy_user.id)
            assert stored_before.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert stored_before.verify_password("LegacyPass!123")
            assert stored_before.verify_password_result("LegacyPass!123").needs_rehash

            upgraded = await persistence.upgrade_user_password_hash(
                legacy_user.id,
                "LegacyPass!123",
            )

            assert upgraded.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert upgraded.password_salt is None
            assert upgraded.password_hash.startswith(b"$argon2id$")
            assert upgraded.verify_password("LegacyPass!123")
            assert not upgraded.verify_password_result("LegacyPass!123").needs_rehash
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_password_hash_upgrade_rejects_caller_owned_transaction(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "nested-upgrade.db")
        try:
            legacy_user = _legacy_user(
                "nested-upgrade@example.com",
                "LegacyPass!123",
            )
            legacy_user.username = "committed-user"
            await persistence._create_user_unchecked(legacy_user)
            auth_state_before = persistence.conn.execute(
                """
                SELECT password_hash, password_salt, password_scheme
                FROM users
                WHERE id = ?
                """,
                (str(legacy_user.id),),
            ).fetchone()

            persistence.conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                ("caller-pending", str(legacy_user.id)),
            )

            try:
                with pytest.raises(
                    RuntimeError,
                    match="Password hash upgrade cannot run inside an existing transaction",
                ):
                    await persistence.upgrade_user_password_hash(
                        legacy_user.id,
                        "LegacyPass!123",
                    )

                assert persistence.conn.in_transaction is True
                assert persistence.conn.execute(
                    "SELECT username FROM users WHERE id = ?",
                    (str(legacy_user.id),),
                ).fetchone() == ("caller-pending",)
                with sqlite3.connect(persistence.db_path) as verifier:
                    assert verifier.execute(
                        "SELECT username FROM users WHERE id = ?",
                        (str(legacy_user.id),),
                    ).fetchone() == ("committed-user",)

                assert persistence.conn.execute(
                    """
                    SELECT password_hash, password_salt, password_scheme
                    FROM users
                    WHERE id = ?
                    """,
                    (str(legacy_user.id),),
                ).fetchone() == auth_state_before
            finally:
                persistence.conn.rollback()

            stored = await persistence.get_user_by_id(legacy_user.id)
            assert stored.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert stored.verify_password_result("LegacyPass!123").needs_rehash
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_legacy_pbkdf2_user_is_upgraded_after_successful_login(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "login-upgrade.db")
        try:
            legacy_user = _legacy_user("login-upgrade@example.com", "LegacyPass!123")
            await persistence._create_user_unchecked(legacy_user)

            session = _FakeSession(persistence)
            form = _mount_login_form(
                session,
                identifier=legacy_user.email,
                password="LegacyPass!123",
            )

            await LoginForm.login(form)

            stored = await persistence.get_user_by_id(legacy_user.id)
            assert stored.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert stored.password_salt is None
            assert session.navigation_target == "/app/dashboard"
            assert session[UserSettings].auth_token != ""
            assert session[AppUser].password_scheme == password_utils.HASH_SCHEME_ARGON2ID
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_wrong_login_password_does_not_upgrade_legacy_row(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "login-wrong-upgrade.db")
        try:
            legacy_user = _legacy_user("login-wrong@example.com", "LegacyPass!123")
            await persistence._create_user_unchecked(legacy_user)

            session = _FakeSession(persistence)
            form = _mount_login_form(
                session,
                identifier=legacy_user.email,
                password="WrongPass!123",
            )

            await LoginForm.login(form)

            stored = await persistence.get_user_by_id(legacy_user.id)
            assert stored.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert stored.password_salt is not None
            assert session.navigation_target is None
            assert session[UserSettings].auth_token == ""
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_legacy_pbkdf2_user_is_not_upgraded_before_mfa_success(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "login-mfa-upgrade.db")
        try:
            legacy_user = _legacy_user("login-mfa@example.com", "LegacyPass!123")
            await persistence._create_user_unchecked(legacy_user)
            secret = pyotp.random_base32()
            persistence.set_2fa_secret(legacy_user.id, secret)

            session = _FakeSession(persistence)
            form = _mount_login_form(
                session,
                identifier=legacy_user.email,
                password="LegacyPass!123",
                verification_code="000000",
            )

            await LoginForm.login(form)

            stored_after_bad_mfa = await persistence.get_user_by_id(legacy_user.id)
            assert stored_after_bad_mfa.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert session.navigation_target is None
            assert session[UserSettings].auth_token == ""

            form.verification_code = pyotp.TOTP(secret).now()
            await LoginForm.login(form)

            stored_after_good_mfa = await persistence.get_user_by_id(legacy_user.id)
            assert stored_after_good_mfa.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert session.navigation_target == "/app/dashboard"
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_wrong_legacy_password_does_not_upgrade_row(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "wrong-upgrade.db")
        try:
            legacy_user = _legacy_user("wrong-upgrade@example.com", "LegacyPass!123")
            await persistence._create_user_unchecked(legacy_user)

            try:
                await persistence.upgrade_user_password_hash(
                    legacy_user.id,
                    "WrongPass!123",
                )
                upgraded = True
            except ValueError:
                upgraded = False

            stored = await persistence.get_user_by_id(legacy_user.id)
            assert upgraded is False
            assert stored.password_scheme == password_utils.HASH_SCHEME_PBKDF2_SHA256
            assert stored.password_salt is not None
            assert stored.verify_password("LegacyPass!123")
        finally:
            persistence.close()

    asyncio.run(scenario())


def test_upgrade_helper_noops_for_existing_argon2id_row(tmp_path: Path):
    async def scenario():
        persistence = Persistence(db_path=tmp_path / "noop-upgrade.db")
        try:
            user = AppUser.create_new_user_with_default_settings(
                email="noop-upgrade@example.com",
                password="StrongPass!123",
            )
            await persistence._create_user_unchecked(user)

            refreshed = await persistence.upgrade_user_password_hash(
                user.id,
                "StrongPass!123",
            )

            assert refreshed.password_scheme == password_utils.HASH_SCHEME_ARGON2ID
            assert refreshed.password_hash == user.password_hash
            assert refreshed.verify_password("StrongPass!123")
        finally:
            persistence.close()

    asyncio.run(scenario())


def _legacy_user(email: str, password: str) -> AppUser:
    password_salt = b"legacy-salt-for-" + email.encode("utf-8")
    return AppUser(
        id=uuid.uuid4(),
        email=email,
        username=None,
        created_at=datetime.now(timezone.utc),
        password_hash=AppUser.get_password_hash(password, password_salt),
        password_salt=password_salt,
        password_scheme=password_utils.HASH_SCHEME_PBKDF2_SHA256,
        auth_provider="password",
        role="user",
        is_verified=True,
        primary_currency_updated_at=datetime.now(timezone.utc) + timedelta(0),
    )


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(self, persistence: Persistence, client_ip: str = "198.51.100.40"):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=""),
        }
        self.client_ip = client_ip
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self.running_as_website = True
        self.navigation_target: str | None = None
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        try:
            return self._attachments[key]
        except KeyError as exc:
            raise KeyError(key) from exc

    def attach(self, value) -> None:
        self._attachments[type(value)] = value

    def navigate_to(self, target_url: str, *, replace: bool = False) -> None:
        self.navigation_target = target_url

    def _register_dirty_component(self, component) -> None:
        pass


def _mount_login_form(session: _FakeSession, **attributes) -> LoginForm:
    component = object.__new__(LoginForm)
    component._session_ = session
    component._properties_assigned_after_creation_ = set()
    component.force_refresh = lambda: None
    component._currently_logging_in = False
    component.pending_verification_email = ""
    component.banner_style = "danger"
    component.error_message = ""
    component.verification_code = ""
    component.on_toggle_form = None
    for key, value in attributes.items():
        setattr(component, key, value)
    return component
