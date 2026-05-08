import asyncio
import builtins
import concurrent.futures
from pathlib import Path
from threading import Barrier

from app.config import config
from app.data_models import AppUser
from app.permissions import get_default_role, get_first_user_role
from app.persistence import Persistence
from app.scripts import bootstrap_root, prestart


STRONG_PASSWORD = "VeryStrongPass!9"


async def _list_users_async(db_path: Path):
    persistence = Persistence(db_path=db_path)
    try:
        return await persistence.list_users()
    finally:
        persistence.close()


def _list_users(db_path: Path):
    return asyncio.run(_list_users_async(db_path))


def _user_count(db_path: Path) -> int:
    persistence = Persistence(db_path=db_path)
    try:
        return persistence.get_user_count()
    finally:
        persistence.close()


def test_bootstrap_root_creates_one_verified_root(tmp_path: Path, capsys) -> None:
    db_path = tmp_path / "bootstrap.db"

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--password",
            STRONG_PASSWORD,
        ]
    )

    assert exit_code == 0
    output = capsys.readouterr()
    assert STRONG_PASSWORD not in output.out
    assert STRONG_PASSWORD not in output.err

    users = _list_users(db_path)
    assert len(users) == 1
    user = users[0]
    assert user.email == "owner@example.com"
    assert user.username is None
    assert user.role == get_first_user_role()
    assert user.is_verified is True
    assert user.verify_password(STRONG_PASSWORD)


def test_bootstrap_root_empty_command_prompts_for_email_and_password(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "prompted.db"
    prompts = []

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return "prompted@example.com"

    def fake_getpass(prompt: str) -> str:
        prompts.append(prompt)
        return STRONG_PASSWORD

    monkeypatch.setattr(bootstrap_root, "DEFAULT_DB_PATH", db_path)
    monkeypatch.setattr(builtins, "input", fake_input)
    monkeypatch.setattr(bootstrap_root.getpass, "getpass", fake_getpass)

    assert bootstrap_root.main([]) == 0

    output = capsys.readouterr()
    assert STRONG_PASSWORD not in output.out
    assert STRONG_PASSWORD not in output.err
    assert prompts == ["Root email: ", "Root password: "]
    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].email == "prompted@example.com"


def test_bootstrap_root_username_only_creates_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "username-only.db"

    def fail_if_prompted(prompt: str) -> str:
        raise AssertionError(f"Unexpected prompt: {prompt}")

    monkeypatch.setattr(builtins, "input", fail_if_prompted)
    assert config.REQUIRE_VALID_EMAIL is True

    assert bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--username",
            "owner",
            "--password",
            STRONG_PASSWORD,
        ]
    ) == 0

    assert config.REQUIRE_VALID_EMAIL is True
    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].email == "owner"
    assert users[0].username == "owner"
    assert users[0].role == get_first_user_role()
    assert users[0].is_verified is True


def test_bootstrap_root_second_run_is_noop(tmp_path: Path) -> None:
    db_path = tmp_path / "noop.db"

    assert bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            STRONG_PASSWORD,
        ]
    ) == 0
    assert bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "other@example.com",
            "--username",
            "other",
            "--password",
            "AnotherStrongPass!9",
        ]
    ) == 0

    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].email == "owner@example.com"
    assert users[0].username == "owner"


def test_concurrent_bootstrap_root_creates_one_verified_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "concurrent-bootstrap.db"
    thread_count = 2
    count_barrier = Barrier(thread_count)

    class RaceBootstrapPersistence(Persistence):
        def get_user_count(self) -> int:
            count = super().get_user_count()
            if count == 0:
                count_barrier.wait(timeout=10)
            return count

    monkeypatch.setattr(bootstrap_root, "Persistence", RaceBootstrapPersistence)

    def run_bootstrap(index: int) -> int:
        return bootstrap_root.main(
            [
                "--db-path",
                str(db_path),
                "--email",
                f"owner-{index}@example.com",
                "--password",
                STRONG_PASSWORD,
            ]
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = list(executor.map(run_bootstrap, range(thread_count)))

    assert results == [0, 0]

    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].role == get_first_user_role()
    assert users[0].is_verified is True


def test_bootstrap_root_strict_missing_credentials_exits_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "missing.db"
    monkeypatch.setattr(builtins, "input", lambda prompt: "")

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--strict",
            "--password",
            STRONG_PASSWORD,
        ]
    )

    assert exit_code == bootstrap_root.MISSING_CREDENTIALS_EXIT_CODE
    assert _user_count(db_path) == 0


def test_bootstrap_root_rejects_weak_password_unless_allowed(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "weak.db"

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            "weak",
        ]
    )

    assert exit_code == bootstrap_root.MISSING_CREDENTIALS_EXIT_CODE
    assert _user_count(db_path) == 0

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            "weak",
            "--allow-weak-password",
        ]
    )

    assert exit_code == 0
    assert len(_list_users(db_path)) == 1


def test_bootstrap_root_db_path_targets_requested_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    default_db_path = tmp_path / "default.db"
    target_db_path = tmp_path / "target.db"
    monkeypatch.setattr(bootstrap_root, "DEFAULT_DB_PATH", default_db_path)

    assert bootstrap_root.main(
        [
            "--db-path",
            str(target_db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            STRONG_PASSWORD,
        ]
    ) == 0

    assert target_db_path.exists()
    assert not default_db_path.exists()


def test_explicit_bootstrap_creates_root_when_public_fallback_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "strict-public-disabled.db"
    monkeypatch.setattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP", False)

    assert bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            STRONG_PASSWORD,
        ]
    ) == 0

    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].role == get_first_user_role()


def test_prestart_strict_bootstrap_fails_empty_database(
    tmp_path: Path,
    capsys,
) -> None:
    db_path = tmp_path / "prestart-empty.db"

    exit_code = prestart.main(
        ["--db-path", str(db_path), "--strict-bootstrap"]
    )

    assert exit_code == 2
    output = capsys.readouterr()
    assert "Run python -m app.scripts.bootstrap_root" in output.err
    assert db_path.exists()
    assert _user_count(db_path) == 0


def test_prestart_strict_bootstrap_fails_without_verified_root(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "prestart-unverified-user.db"
    monkeypatch.setattr(config, "ALLOW_PUBLIC_ROOT_BOOTSTRAP", False)

    persistence = Persistence(db_path=db_path)
    try:
        user = AppUser.create_new_user_with_default_settings(
            email="unverified@example.com",
            password=STRONG_PASSWORD,
        )
        asyncio.run(persistence.create_user(user))
    finally:
        persistence.close()

    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].role == get_default_role()
    assert users[0].is_verified is False

    assert prestart.main(
        ["--db-path", str(db_path), "--strict-bootstrap"]
    ) == 2
    output = capsys.readouterr()
    assert "database already contains users" in output.err
    assert "bootstrap_root only creates the first account" in output.err
    assert "will not modify this DB" in output.err
    assert "Run python -m app.scripts.bootstrap_root" not in output.err


def test_prestart_strict_bootstrap_passes_after_bootstrap(tmp_path: Path) -> None:
    db_path = tmp_path / "prestart-ready.db"
    assert bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            "owner",
            "--password",
            STRONG_PASSWORD,
        ]
    ) == 0

    assert prestart.main(
        ["--db-path", str(db_path), "--strict-bootstrap"]
    ) == 0
