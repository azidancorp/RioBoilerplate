import asyncio
import builtins
import concurrent.futures
import os
import shutil
import subprocess
import sys
from pathlib import Path
from threading import Barrier

import app as app_module

from app.config import config
from app.data_models import AppUser
from app.permissions import get_default_role, get_highest_privilege_role
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
    assert user.role == get_highest_privilege_role()
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
    assert users[0].role == get_highest_privilege_role()
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
    assert users[0].role == get_highest_privilege_role()
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


def test_bootstrap_root_preflight_uses_canonical_account_context(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "canonical-context.db"
    raw_username = "AlphaBetaGamma!9<"
    canonical_username = "AlphaBetaGamma!9&lt;"
    creation_calls = 0

    class TrackingPersistence(Persistence):
        async def create_verified_root_user_if_empty(self, **kwargs) -> bool:
            nonlocal creation_calls
            creation_calls += 1
            return await super().create_verified_root_user_if_empty(**kwargs)

    monkeypatch.setattr(bootstrap_root, "Persistence", TrackingPersistence)

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            raw_username,
            "--password",
            canonical_username,
        ]
    )

    assert exit_code == bootstrap_root.MISSING_CREDENTIALS_EXIT_CODE
    assert creation_calls == 0
    assert "account identifier" in capsys.readouterr().err
    assert _user_count(db_path) == 0

    exit_code = bootstrap_root.main(
        [
            "--db-path",
            str(db_path),
            "--email",
            "owner@example.com",
            "--username",
            raw_username,
            "--password",
            canonical_username,
            "--allow-weak-password",
        ]
    )

    assert exit_code == 0
    assert creation_calls == 1
    users = _list_users(db_path)
    assert len(users) == 1
    assert users[0].username == canonical_username
    assert users[0].verify_password(canonical_username)


def test_bootstrap_root_acknowledgement_respects_strict_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "strict-weak.db"
    monkeypatch.setattr(config, "ALLOW_WEAK_PASSWORDS", False)

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

    assert exit_code == bootstrap_root.MISSING_CREDENTIALS_EXIT_CODE
    assert _user_count(db_path) == 0


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


def test_explicit_bootstrap_creates_root(tmp_path: Path) -> None:
    db_path = tmp_path / "explicit-bootstrap.db"

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
    assert users[0].role == get_highest_privilege_role()


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
    capsys,
) -> None:
    db_path = tmp_path / "prestart-unverified-user.db"

    persistence = Persistence(db_path=db_path)
    try:
        user = AppUser.create_new_user_with_default_settings(
            email="unverified@example.com",
            password=STRONG_PASSWORD,
        )
        asyncio.run(persistence._create_user_unchecked(user))
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


def test_prestart_strict_bootstrap_passes_after_bootstrap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "prestart-ready.db"
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", False)
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

    assert prestart.main(["--db-path", str(db_path), "--strict-bootstrap"]) == 0


def test_prestart_secure_cookie_requirement_fails_before_touching_database(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "secure-cookie-disabled.db"
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", False)

    exit_code = prestart.main(
        [
            "--db-path",
            str(db_path),
            "--strict-bootstrap",
            "--require-secure-auth-cookie",
        ]
    )

    assert exit_code == 3
    output = capsys.readouterr()
    assert "authentication cookies are not Secure" in output.err
    assert "AUTH_TOKEN_COOKIE_SECURE = True" in output.err
    assert not db_path.exists()


def test_prestart_secure_cookie_requirement_passes_for_ready_database(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "secure-cookie-ready.db"
    assert (
        bootstrap_root.main(
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
        )
        == 0
    )
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)
    monkeypatch.setattr(config, "APP_URL", "https://app.example.test")
    monkeypatch.setattr(config, "OAUTH_COOKIE_SECURE", True)

    assert prestart.main(
        [
            "--db-path",
            str(db_path),
            "--strict-bootstrap",
            "--require-secure-auth-cookie",
        ]
    ) == 0


def test_prestart_secure_cookie_requirement_accepts_canonical_origins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)
    monkeypatch.setattr(config, "ENABLE_GOOGLE_LOGIN", False)

    for index, app_url in enumerate(
        (
            "https://app.example.test",
            "https://app.example.test/",
            "https://app.example.test:8443",
            "https://127.0.0.1",
            "https://[2001:db8::1]:8443",
            "https://xn--bcher-kva.example",
            "https://xn--fa-hia.example",
            "https://xn--strae-oqa.example",
        )
    ):
        db_path = tmp_path / f"canonical-origin-{index}.db"
        monkeypatch.setattr(config, "APP_URL", app_url)

        assert (
            prestart.main(
                [
                    "--db-path",
                    str(db_path),
                    "--require-secure-auth-cookie",
                ]
            )
            == 0
        )
        assert db_path.exists()


def test_prestart_secure_cookie_requirement_rejects_noncanonical_origins(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)

    for index, app_url in enumerate(
        (
            "https://app.example.test/base",
            "https://app.example.test?wrong=1",
            "https://app.example.test/#fragment",
            "https://app.example.test:not-a-port",
            "https://app.example.test:70000",
            "https://app.example.test:",
            "https://app.example.test:0",
            "https://app.example.test?",
            "https://app.example.test#",
            "https://app.example.test/#",
            "https://app.example.test ",
            "https://app.example.test\\evil",
            "https://%61pp.example.test",
            "https://app.exämple.test",
            "https://-app.example.test",
            "https://app.example.test.",
            "https://app.example.test\x7f",
            "https://0x7f000001",
            "https://0x7f.0.0.1",
            "https://example.123",
            "https://example.0x7f",
            "https://xn--a.example",
            "https://xn--abc.example",
            "https://xn--0.example",
            "https://[v1.a]",
            "https://0x",
            "https://1.0x",
            "https://example.0x",
            "https://xn--00b.example",
        )
    ):
        db_path = tmp_path / f"noncanonical-origin-{index}.db"
        monkeypatch.setattr(config, "APP_URL", app_url)

        assert (
            prestart.main(
                [
                    "--db-path",
                    str(db_path),
                    "--require-secure-auth-cookie",
                ]
            )
            == 3
        )
        assert "canonical HTTPS origin" in capsys.readouterr().err
        assert not db_path.exists()


def test_prestart_does_not_require_canonical_origin_without_production_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "ungated-app-url.db"
    monkeypatch.setattr(config, "APP_URL", "https://example.test:bad-port/path")

    assert prestart.main(["--db-path", str(db_path)]) == 0
    assert db_path.exists()


def test_prestart_secure_cookie_requirement_rejects_plaintext_app_url(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "secure-cookie-http-url.db"
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)
    monkeypatch.setattr(config, "APP_URL", "http://app.example.test")

    exit_code = prestart.main(
        [
            "--db-path",
            str(db_path),
            "--require-secure-auth-cookie",
        ]
    )

    assert exit_code == 3
    output = capsys.readouterr()
    assert "APP_URL" in output.err
    assert "https://" in output.err
    assert not db_path.exists()


def test_prestart_secure_cookie_requirement_rejects_insecure_oauth_cookie(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "insecure-oauth-cookie.db"
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)
    monkeypatch.setattr(config, "APP_URL", "https://app.example.test")
    monkeypatch.setattr(config, "ENABLE_GOOGLE_LOGIN", True)
    monkeypatch.setattr(config, "SESSION_SECRET_KEY", "session-secret")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setattr(config, "OAUTH_COOKIE_SECURE", False)

    exit_code = prestart.main(
        [
            "--db-path",
            str(db_path),
            "--require-secure-auth-cookie",
        ]
    )

    assert exit_code == 3
    output = capsys.readouterr()
    assert "Production OAuth is configured" in output.err
    assert "OAUTH_COOKIE_SECURE = True" in output.err
    assert not db_path.exists()


def test_prestart_allows_nonsecure_oauth_cookie_when_oauth_is_disabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "oauth-disabled.db"
    monkeypatch.setattr(config, "AUTH_TOKEN_COOKIE_SECURE", True)
    monkeypatch.setattr(config, "APP_URL", "https://app.example.test")
    monkeypatch.setattr(config, "ENABLE_GOOGLE_LOGIN", False)
    monkeypatch.setattr(config, "SESSION_SECRET_KEY", "session-secret")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(config, "GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setattr(config, "OAUTH_COOKIE_SECURE", False)

    assert prestart.main(
        [
            "--db-path",
            str(db_path),
            "--require-secure-auth-cookie",
        ]
    ) == 0
    assert db_path.exists()


def test_prestart_production_email_rejects_outbox_before_touching_database(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "production-outbox.db"
    monkeypatch.setattr(config, "EMAIL_METHOD", "outbox")

    exit_code = prestart.main(
        ["--db-path", str(db_path), "--require-production-email"]
    )

    assert exit_code == 3
    assert "local development only" in capsys.readouterr().err
    assert not db_path.exists()


def test_prestart_production_resend_requires_api_key_before_database(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "resend-without-key.db"
    monkeypatch.setattr(config, "EMAIL_METHOD", "resend")
    monkeypatch.setattr(config, "DEFAULT_EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "RESEND_API_KEY", "")

    exit_code = prestart.main(
        ["--db-path", str(db_path), "--require-production-email"]
    )

    assert exit_code == 3
    assert "requires RESEND_API_KEY" in capsys.readouterr().err
    assert not db_path.exists()


def test_prestart_production_smtp_rejects_insecure_or_partial_credentials(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(config, "EMAIL_METHOD", "smtp")
    monkeypatch.setattr(config, "DEFAULT_EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_USERNAME", "smtp-user")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "smtp-password")
    monkeypatch.setattr(config, "SMTP_USE_TLS", False)

    insecure_db = tmp_path / "insecure-smtp.db"
    assert prestart.main(
        ["--db-path", str(insecure_db), "--require-production-email"]
    ) == 3
    assert "requires SMTP_USE_TLS=True" in capsys.readouterr().err
    assert not insecure_db.exists()

    monkeypatch.setattr(config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(config, "SMTP_PASSWORD", "")
    partial_db = tmp_path / "partial-smtp-credentials.db"
    assert prestart.main(
        ["--db-path", str(partial_db), "--require-production-email"]
    ) == 3
    assert "must be configured together" in capsys.readouterr().err
    assert not partial_db.exists()


def test_prestart_production_email_accepts_resend_and_secure_smtp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(config, "DEFAULT_EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "EMAIL_METHOD", "resend")
    monkeypatch.setattr(config, "RESEND_API_KEY", "re_test")
    resend_db = tmp_path / "ready-resend.db"
    assert prestart.main(
        ["--db-path", str(resend_db), "--require-production-email"]
    ) == 0

    monkeypatch.setattr(config, "EMAIL_METHOD", "smtp")
    monkeypatch.setattr(config, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "SMTP_USE_TLS", True)
    monkeypatch.setattr(config, "SMTP_USERNAME", "")
    monkeypatch.setattr(config, "SMTP_PASSWORD", "")
    smtp_db = tmp_path / "ready-smtp.db"
    assert prestart.main(
        ["--db-path", str(smtp_db), "--require-production-email"]
    ) == 0


def test_prestart_email_verification_requirement_fails_when_disabled(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    db_path = tmp_path / "verification-disabled.db"
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", False)

    exit_code = prestart.main(
        ["--db-path", str(db_path), "--require-email-verification"]
    )

    assert exit_code == 3
    assert "REQUIRE_EMAIL_VERIFICATION must be True" in capsys.readouterr().err
    assert not db_path.exists()


def test_prestart_email_verification_requirement_passes_when_enabled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "verification-enabled.db"
    monkeypatch.setattr(config, "REQUIRE_EMAIL_VERIFICATION", True)

    assert prestart.main(
        ["--db-path", str(db_path), "--require-email-verification"]
    ) == 0


def test_prestart_module_invocation_detection_is_exact() -> None:
    assert app_module._is_prestart_module_invocation(
        ["python", "-X", "dev", "-m", "app.scripts.prestart"]
    )
    assert app_module._is_prestart_module_invocation(
        ["python", "-imapp.scripts.prestart", "--strict-bootstrap"]
    )
    assert not app_module._is_prestart_module_invocation(
        ["python", "-m", "app.scripts.bootstrap_root"]
    )
    assert not app_module._is_prestart_module_invocation(
        ["python", "worker.py", "-m", "app.scripts.prestart"]
    )
    assert not app_module._is_prestart_module_invocation(
        ["python", "-c", "pass", "-m", "app.scripts.prestart"]
    )


def test_prestart_module_reports_plaintext_url_before_app_import_failure(
    tmp_path: Path,
) -> None:
    source_package = Path(__file__).resolve().parents[1] / "app"
    copied_project = tmp_path / "project"
    copied_package = copied_project / "app"
    shutil.copytree(
        source_package,
        copied_package,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )

    copied_config = copied_package / "config.py"
    config_source = copied_config.read_text(encoding="utf-8")
    insecure_default = "AUTH_TOKEN_COOKIE_SECURE: bool = False"
    assert insecure_default in config_source
    copied_config.write_text(
        config_source.replace(
            insecure_default,
            "AUTH_TOKEN_COOKIE_SECURE: bool = True",
            1,
        ),
        encoding="utf-8",
    )

    db_path = tmp_path / "must-not-exist.db"
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.scripts.prestart",
            "--db-path",
            str(db_path),
            "--require-secure-auth-cookie",
        ],
        cwd=copied_project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 3
    assert "authentication cookies require APP_URL" in result.stderr
    assert "Traceback" not in result.stderr
    assert not db_path.exists()

    runtime_import = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=copied_project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert runtime_import.returncode != 0
    assert "Secure production cookies require" in runtime_import.stderr


def test_railway_start_is_gated_by_strict_bootstrap() -> None:
    railway_config = (
        Path(__file__).resolve().parents[2] / "railway.toml"
    ).read_text(encoding="utf-8")

    strict_check = (
        "python -m app.scripts.prestart --strict-bootstrap "
        "--require-secure-auth-cookie --require-production-email "
        "--require-email-verification"
    )
    public_start = "exec rio run"
    assert strict_check in railway_config
    assert public_start in railway_config
    assert railway_config.index(strict_check) < railway_config.index(public_start)
