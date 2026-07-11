#!/usr/bin/env python3
"""One-shot CLI for creating the initial verified root user."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path
from typing import Iterable

from app.config import config
from app.data_models import AppUser
from app.permissions import get_highest_privilege_role
from app.persistence import DEFAULT_DB_PATH, Persistence
from app.password_policy import evaluate_new_password


MISSING_CREDENTIALS_EXIT_CODE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create the first verified root user when the database is empty.",
    )
    parser.add_argument(
        "--email",
        help="Email address for the root user. Prompted if neither email nor username is supplied.",
    )
    parser.add_argument(
        "--username",
        help="Optional username/display handle. Can be used without --email.",
    )
    parser.add_argument(
        "--password",
        help="Root password. Omit to prompt securely with getpass.",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="SQLite database path. Defaults to the app runtime database.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit nonzero when the database is empty but credentials are missing.",
    )
    parser.add_argument(
        "--allow-weak-password",
        action="store_true",
        help="Allow a password below the configured strength threshold.",
    )
    return parser


def _normalize_value(value: str | None) -> str:
    return (value or "").strip()


def _warn_missing(missing_fields: list[str], *, strict: bool) -> int:
    message = (
        "Root bootstrap skipped because the database is empty but missing "
        f"credential field(s): {', '.join(missing_fields)}. "
        "Run python -m app.scripts.bootstrap_root and enter the requested "
        "identifier and password, or provide --email/--username and --password."
    )
    print(("ERROR: " if strict else "WARNING: ") + message, file=sys.stderr)
    return MISSING_CREDENTIALS_EXIT_CODE if strict else 0


def _prompt_input(prompt: str) -> str | None:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print("\nERROR: Root bootstrap prompt was cancelled.", file=sys.stderr)
        return None


async def bootstrap_root(args: argparse.Namespace) -> int:
    db_path = args.db_path or DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)

    email = _normalize_value(args.email)
    username = _normalize_value(args.username)
    password = args.password

    pers = Persistence(
        db_path=db_path,
        allow_username_login=config.ALLOW_USERNAME_LOGIN,
    )
    try:
        if pers.get_user_count() > 0:
            print("Root bootstrap skipped: users already exist.")
            return 0

        if not email and not username:
            prompted_email = _prompt_input("Root email: ")
            if prompted_email is None:
                return MISSING_CREDENTIALS_EXIT_CODE
            email = _normalize_value(prompted_email)

        if password is None:
            try:
                password = getpass.getpass("Root password: ")
            except (EOFError, KeyboardInterrupt):
                print("\nERROR: Root bootstrap password prompt was cancelled.", file=sys.stderr)
                return MISSING_CREDENTIALS_EXIT_CODE

        password = password or ""
        if not email and not username:
            return _warn_missing(["email or username"], strict=args.strict)
        if not password:
            return _warn_missing(["password"], strict=args.strict)

        password_policy = evaluate_new_password(
            password,
            acknowledged_weak=args.allow_weak_password,
            allow_weak=args.allow_weak_password,
        )
        if not password_policy.ok:
            print(
                "ERROR: Root password is too weak. Choose a stronger password "
                f"(minimum strength: {config.MIN_PASSWORD_STRENGTH}) or pass "
                "--allow-weak-password for a controlled local/test bootstrap.",
                file=sys.stderr,
            )
            return MISSING_CREDENTIALS_EXIT_CODE

        email_for_storage = email or username
        if not email_for_storage:
            return _warn_missing(["email or username"], strict=args.strict)

        user = AppUser.create_new_user_with_default_settings(
            email=email_for_storage,
            password=password,
            username=username or None,
        )
        user.role = get_highest_privilege_role()
        user.is_verified = True

        original_require_valid_email = config.REQUIRE_VALID_EMAIL
        if not email:
            config.REQUIRE_VALID_EMAIL = False
        try:
            created = await pers.create_verified_root_user_if_empty(user)
        finally:
            config.REQUIRE_VALID_EMAIL = original_require_valid_email
    finally:
        pers.close()

    if not created:
        print("Root bootstrap skipped: users already exist.")
        return 0

    print(f"Created verified root user: {email_for_storage}")
    return 0


async def main_async(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return await bootstrap_root(args)


def main(argv: Iterable[str] | None = None) -> int:
    return asyncio.run(main_async(argv))


if __name__ == "__main__":
    raise SystemExit(main())
