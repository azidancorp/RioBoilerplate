#!/usr/bin/env python3
"""Prestart checks for deployment service managers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from fastapi import HTTPException

from app.api.health import check_sqlite_health
from app.config import config
from app.oauth_clients import is_google_login_configured
from app.persistence import DEFAULT_DB_PATH, Persistence
from app.rio_cookie_security import canonical_http_origin
from app.validation import SecuritySanitizer


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Initialize the SQLite schema and verify deployment readiness.",
    )
    parser.add_argument(
        "--strict-bootstrap",
        action="store_true",
        help="Fail unless a verified root user exists after schema initialization.",
    )
    parser.add_argument(
        "--require-secure-auth-cookie",
        action="store_true",
        help=(
            "Fail unless browser authentication and configured OAuth cookies "
            "are Secure."
        ),
    )
    parser.add_argument(
        "--require-production-email",
        action="store_true",
        help="Fail unless a secure external email provider is configured.",
    )
    parser.add_argument(
        "--require-email-verification",
        action="store_true",
        help="Fail unless signup requires verified email ownership.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="SQLite database path. Defaults to the app runtime database.",
    )
    return parser


def _is_canonical_https_origin(value: str) -> bool:
    try:
        origin = canonical_http_origin(value)
    except ValueError:
        return False
    return origin.startswith("https://")


def _production_email_configuration_error() -> str | None:
    method = (config.EMAIL_METHOD or "").strip().lower()
    if method == "outbox":
        return "EMAIL_METHOD='outbox' is for local development only."
    if method not in {"resend", "smtp"}:
        return "EMAIL_METHOD must be 'resend' or 'smtp' in production."

    try:
        SecuritySanitizer.validate_email_format(
            config.DEFAULT_EMAIL_SENDER,
            require_valid=True,
        )
    except HTTPException:
        return "DEFAULT_EMAIL_SENDER must be a valid production email address."

    if method == "resend":
        if not (config.RESEND_API_KEY or "").strip():
            return "EMAIL_METHOD='resend' requires RESEND_API_KEY."
        return None

    if not (config.SMTP_HOST or "").strip():
        return "EMAIL_METHOD='smtp' requires SMTP_HOST."
    if not config.SMTP_USE_TLS:
        return "EMAIL_METHOD='smtp' requires SMTP_USE_TLS=True."
    if bool((config.SMTP_USERNAME or "").strip()) != bool(
        config.SMTP_PASSWORD or ""
    ):
        return "SMTP_USERNAME and SMTP_PASSWORD must be configured together."
    return None


def run_prestart(args: argparse.Namespace) -> int:
    if args.require_secure_auth_cookie and not config.AUTH_TOKEN_COOKIE_SECURE:
        print(
            "ERROR: Production authentication cookies are not Secure. Set "
            "AUTH_TOKEN_COOKIE_SECURE = True in app/app/config.py before "
            "starting the public service.",
            file=sys.stderr,
        )
        return 3

    if args.require_secure_auth_cookie and not _is_canonical_https_origin(
        config.APP_URL
    ):
        print(
            "ERROR: Secure production authentication cookies require APP_URL "
            "to be a canonical HTTPS origin such as https://example.com in "
            "app/app/config.py.",
            file=sys.stderr,
        )
        return 3

    if (
        args.require_secure_auth_cookie
        and is_google_login_configured()
        and not config.OAUTH_COOKIE_SECURE
    ):
        print(
            "ERROR: Production OAuth is configured, but its state/nonce "
            "cookie is not Secure. Set OAUTH_COOKIE_SECURE = True in "
            "app/app/config.py before starting the public service.",
            file=sys.stderr,
        )
        return 3

    if args.require_production_email:
        email_error = _production_email_configuration_error()
        if email_error:
            print(
                f"ERROR: Production email check failed: {email_error}",
                file=sys.stderr,
            )
            return 3

    if args.require_email_verification and not config.REQUIRE_EMAIL_VERIFICATION:
        print(
            "ERROR: Production email-verification check failed: "
            "REQUIRE_EMAIL_VERIFICATION must be True in app/app/config.py so "
            "password accounts cannot authenticate before proving control of "
            "their email address.",
            file=sys.stderr,
        )
        return 3

    db_path = args.db_path or DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    pers = Persistence(
        db_path=db_path,
        allow_username_login=config.ALLOW_USERNAME_LOGIN,
    )
    try:
        user_count = pers.get_user_count()
        has_verified_root = pers.has_verified_root_user()
    finally:
        pers.close()

    health = check_sqlite_health(db_path)
    if not health.ok:
        print(f"ERROR: Prestart health check failed: {health.code}", file=sys.stderr)
        return 1

    if args.strict_bootstrap and not has_verified_root:
        if user_count == 0:
            detail = (
                "no verified root user exists. Run python -m "
                "app.scripts.bootstrap_root before starting the public service."
            )
        else:
            detail = (
                "the database already contains users, but none is a verified "
                "root user. bootstrap_root only creates the first account for "
                "an empty database and will not modify this DB. Promote and "
                "verify a trusted owner through an administrative recovery or "
                "migration before starting the public service."
            )
        print(
            f"ERROR: Prestart strict bootstrap check failed: {detail}",
            file=sys.stderr,
        )
        return 2

    print("Prestart checks passed.")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return run_prestart(args)


if __name__ == "__main__":
    raise SystemExit(main())
