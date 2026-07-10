import asyncio
import concurrent.futures
import sqlite3
from collections import defaultdict
from pathlib import Path
from threading import Barrier

import pytest

from app.config import config
from app.data_models import AppUser
from app.data_models import UserSettings
from app.pages.login import SignUpForm
from app.permissions import get_default_role, get_highest_privilege_role
from app.persistence import BootstrapRequiredError, Persistence


class _FakeEvent:
    def set(self) -> None:
        pass


class _FakeSession:
    def __init__(self, persistence: Persistence):
        self._attachments = {
            Persistence: persistence,
            UserSettings: UserSettings(auth_token=""),
        }
        self.client_ip = "198.51.100.20"
        self.user_agent = "pytest"
        self.http_headers: dict[str, str] = {}
        self._changed_attributes = defaultdict(set)
        self._refresh_required_event = _FakeEvent()

    def __getitem__(self, key):
        try:
            return self._attachments[key]
        except KeyError as exc:
            raise KeyError(key) from exc


def _mount_signup_form(persistence: Persistence) -> SignUpForm:
    form = object.__new__(SignUpForm)
    form._session_ = _FakeSession(persistence)
    form._properties_assigned_after_creation_ = set()
    form.email = "owner@example.com"
    form.password = "VeryStrongPass!9"
    form.confirm_password = "VeryStrongPass!9"
    form.referral_code = ""
    form.error_message = ""
    form.banner_style = "danger"
    form.is_email_valid = False
    form.passwords_valid = False
    form.acknowledge_weak_password = False
    return form


def _new_root_user() -> AppUser:
    return AppUser.create_new_user_with_default_settings(
        email="root@example.com",
        password="VeryStrongPass!9",
    )


def test_public_root_bootstrap_flag_is_removed() -> None:
    assert not hasattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP")


def test_public_first_signup_is_blocked(tmp_path: Path) -> None:
    db_path = tmp_path / "public-bootstrap-required.db"
    persistence = Persistence(db_path=db_path)
    form = _mount_signup_form(persistence)

    try:
        asyncio.run(SignUpForm.on_sign_up_pressed(form))
    finally:
        persistence.close()

    assert form.banner_style == "danger"
    assert "bootstrap_root" in form.error_message

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_signup_handles_atomic_bootstrap_rejection_after_precheck(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "signup-bootstrap-race.db"
    persistence = Persistence(db_path=db_path)
    form = _mount_signup_form(persistence)
    monkeypatch.setattr(persistence, "get_user_count", lambda: 1)

    try:
        asyncio.run(SignUpForm.on_sign_up_pressed(form))
    finally:
        persistence.close()

    assert form.banner_style == "danger"
    assert "bootstrap_root" in form.error_message
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_public_creation_is_blocked_transactionally_on_empty_database(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "public-creation-empty.db"
    persistence = Persistence(db_path=db_path)
    user = AppUser.create_new_user_with_default_settings(
        email="public@example.com",
        password="VeryStrongPass!9",
    )

    try:
        with pytest.raises(BootstrapRequiredError, match="bootstrap_root"):
            asyncio.run(persistence.create_user(user))
    finally:
        persistence.close()

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM user_currency_ledger").fetchone()[0]
            == 0
        )


def test_public_signup_after_bootstrap_gets_default_role(tmp_path: Path) -> None:
    db_path = tmp_path / "public-after-bootstrap.db"
    persistence = Persistence(db_path=db_path)
    form = _mount_signup_form(persistence)

    async def scenario() -> None:
        assert await persistence.create_verified_root_user_if_empty(_new_root_user())
        await SignUpForm.on_sign_up_pressed(form)

    try:
        asyncio.run(scenario())
    finally:
        persistence.close()

    assert form.banner_style == "success"
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT email, role, is_verified FROM users ORDER BY email"
        ).fetchall()

    assert rows == [
        ("owner@example.com", get_default_role(), 0),
        ("root@example.com", get_highest_privilege_role(), 1),
    ]


def test_public_creation_forces_default_role(tmp_path: Path) -> None:
    persistence = Persistence(db_path=tmp_path / "forced-default.db")

    async def scenario() -> AppUser:
        assert await persistence.create_verified_root_user_if_empty(_new_root_user())
        user = AppUser.create_new_user_with_default_settings(
            email="public@example.com",
            password="VeryStrongPass!9",
        )
        user.role = get_highest_privilege_role()
        await persistence.create_user(user)
        return await persistence.get_user_by_id(user.id)

    try:
        created = asyncio.run(scenario())
    finally:
        persistence.close()

    assert created.role == get_default_role()


def test_public_creation_uses_existing_user_as_initialization_boundary(
    tmp_path: Path,
) -> None:
    persistence = Persistence(db_path=tmp_path / "existing-user-boundary.db")

    async def scenario() -> AppUser:
        existing = AppUser.create_new_user_with_default_settings(
            email="existing@example.com",
            password="VeryStrongPass!9",
        )
        await persistence._create_user_unchecked(existing)
        public = AppUser.create_new_user_with_default_settings(
            email="public@example.com",
            password="VeryStrongPass!9",
        )
        await persistence.create_user(public)
        return await persistence.get_user_by_id(public.id)

    try:
        created = asyncio.run(scenario())
    finally:
        persistence.close()

    assert created.role == get_default_role()


def test_unchecked_internal_creation_never_implicitly_promotes(tmp_path: Path) -> None:
    persistence = Persistence(db_path=tmp_path / "no-implicit-promotion.db")
    user = AppUser.create_new_user_with_default_settings(
        email="internal@example.com",
        password="VeryStrongPass!9",
    )

    try:
        asyncio.run(persistence._create_user_unchecked(user))
        created = asyncio.run(persistence.get_user_by_id(user.id))
    finally:
        persistence.close()

    assert created.role == get_default_role()


def test_concurrent_public_registrations_cannot_initialize_database(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "concurrent-public-empty.db"
    Persistence(db_path=db_path).close()
    start_barrier = Barrier(2)

    def register(index: int) -> type[Exception] | None:
        persistence = Persistence(db_path=db_path)
        user = AppUser.create_new_user_with_default_settings(
            email=f"public-{index}@example.com",
            password="VeryStrongPass!9",
        )
        try:
            start_barrier.wait(timeout=10)
            asyncio.run(persistence.create_user(user))
            return None
        except Exception as exc:
            return type(exc)
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(register, range(2)))

    assert results == [BootstrapRequiredError, BootstrapRequiredError]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_bootstrap_racing_public_registration_never_mints_public_root(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "bootstrap-public-race.db"
    Persistence(db_path=db_path).close()
    start_barrier = Barrier(2)

    def bootstrap() -> bool:
        persistence = Persistence(db_path=db_path)
        try:
            start_barrier.wait(timeout=10)
            return asyncio.run(
                persistence.create_verified_root_user_if_empty(_new_root_user())
            )
        finally:
            persistence.close()

    def register() -> bool:
        persistence = Persistence(db_path=db_path)
        user = AppUser.create_new_user_with_default_settings(
            email="public@example.com",
            password="VeryStrongPass!9",
        )
        try:
            start_barrier.wait(timeout=10)
            asyncio.run(persistence.create_user(user))
            return True
        except BootstrapRequiredError:
            return False
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        bootstrap_result = executor.submit(bootstrap)
        public_result = executor.submit(register)
        assert bootstrap_result.result(timeout=20) is True
        public_created = public_result.result(timeout=20)

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT email, role, is_verified FROM users ORDER BY email"
        ).fetchall()

    assert ("root@example.com", get_highest_privilege_role(), 1) in rows
    if public_created:
        assert ("public@example.com", get_default_role(), 0) in rows
        assert len(rows) == 2
    else:
        assert rows == [("root@example.com", get_highest_privilege_role(), 1)]
