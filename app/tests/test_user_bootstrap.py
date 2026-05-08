import asyncio
import concurrent.futures
import sqlite3
from collections import Counter
from collections import defaultdict
from pathlib import Path
from threading import Barrier

from app.config import config
from app.data_models import AppUser
from app.data_models import UserSettings
from app.pages.login import SignUpForm
from app.permissions import get_default_role, get_first_user_role
from app.persistence import Persistence


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


def test_concurrent_first_user_creation_assigns_one_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "bootstrap-race.db"
    Persistence(db_path=db_path).close()

    thread_count = 2
    start_barrier = Barrier(thread_count)
    count_barrier = Barrier(thread_count)
    real_connect = sqlite3.connect

    class RaceCursor(sqlite3.Cursor):
        def execute(self, sql, parameters=(), /):
            normalized_sql = " ".join(str(sql).split()).upper()
            self._after_user_count = normalized_sql == "SELECT COUNT(*) FROM USERS"
            return super().execute(sql, parameters)

        def fetchone(self):
            row = super().fetchone()
            if (
                getattr(self, "_after_user_count", False)
                and row
                and row[0] == 0
                and not self.connection.in_transaction
            ):
                count_barrier.wait(timeout=10)
            self._after_user_count = False
            return row

    class RaceConnection(sqlite3.Connection):
        def cursor(self, *args, **kwargs):
            kwargs.setdefault("factory", RaceCursor)
            return super().cursor(*args, **kwargs)

    def patched_connect(*args, **kwargs):
        kwargs.setdefault("factory", RaceConnection)
        kwargs.setdefault("timeout", 30)
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", patched_connect)

    def create_user(index: int) -> Exception | None:
        persistence = Persistence(db_path=db_path)
        try:
            user = AppUser.create_new_user_with_default_settings(
                email=f"bootstrap-race-{index}@example.com",
                password="password",
            )
            start_barrier.wait(timeout=10)
            asyncio.run(persistence.create_user(user))
            return None
        except Exception as exc:
            return exc
        finally:
            persistence.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        errors = [
            error
            for error in executor.map(create_user, range(thread_count))
            if error is not None
        ]

    assert errors == []

    with real_connect(db_path) as conn:
        roles = [
            row[0]
            for row in conn.execute("SELECT role FROM users ORDER BY email")
        ]

    role_counts = Counter(roles)
    assert role_counts[get_first_user_role()] == 1
    assert role_counts[get_default_role()] == thread_count - 1


def test_public_first_signup_promotes_root_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "public-bootstrap-enabled.db"
    persistence = Persistence(db_path=db_path)
    monkeypatch.setattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP", True)
    form = _mount_signup_form(persistence)

    try:
        asyncio.run(SignUpForm.on_sign_up_pressed(form))
    finally:
        persistence.close()

    assert form.banner_style == "success"
    assert "successfully signed up" in form.error_message

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT email, role, is_verified FROM users"
        ).fetchall()

    assert rows == [("owner@example.com", get_first_user_role(), 0)]


def test_public_first_signup_is_blocked_when_root_bootstrap_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "public-bootstrap-disabled.db"
    persistence = Persistence(db_path=db_path)
    monkeypatch.setattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP", False)
    form = _mount_signup_form(persistence)

    try:
        asyncio.run(SignUpForm.on_sign_up_pressed(form))
    finally:
        persistence.close()

    assert "bootstrap_root" in form.error_message

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_create_user_keeps_default_role_when_root_bootstrap_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "first-default-role.db"
    persistence = Persistence(db_path=db_path)
    monkeypatch.setattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP", False)

    async def scenario() -> AppUser:
        user = AppUser.create_new_user_with_default_settings(
            email="first-default@example.com",
            password="VeryStrongPass!9",
        )
        await persistence.create_user(user)
        return await persistence.get_user_by_id(user.id)

    try:
        created = asyncio.run(scenario())
    finally:
        persistence.close()

    assert created.role == get_default_role()
