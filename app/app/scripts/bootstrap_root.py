#!/usr/bin/env python3
"""One-shot CLI for creating the initial verified root user."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from pathlib import Path
from typing import Iterable

from fastapi import HTTPException

from app.config import config
from app.persistence import DEFAULT_DB_PATH, Persistence
from app.password_policy import account_password_context, evaluate_bootstrap_password
from app.validation import SecuritySanitizer


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
        help="Acknowledge password quality warnings for the initial root account.",
    )
    return parser


def _normalize_value(value: str | None) -> str:
    return (value or "").strip()


def _canonical_password_account_context(
    *,
    email: str,
    username: str | None,
) -> tuple[str, ...]:
    """Build policy context from the identity persistence will store."""
    normalized_email = SecuritySanitizer.validate_email_format(
        email,
        require_valid=config.REQUIRE_VALID_EMAIL,
    )
    sanitized_username = (
        SecuritySanitizer.sanitize_string(username, 100)
        if username
        else None
    )
    return account_password_context(
        email=normalized_email,
        username=sanitized_username,
    )


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

        email_for_storage = email or username
        if not email_for_storage:
            return _warn_missing(["email or username"], strict=args.strict)

        original_require_valid_email = config.REQUIRE_VALID_EMAIL
        if not email:
            config.REQUIRE_VALID_EMAIL = False
        try:
            try:
                expected_passwords = _canonical_password_account_context(
                    email=email_for_storage,
                    username=username or None,
                )
            except HTTPException as exc:
                print(f"ERROR: {exc.detail}", file=sys.stderr)
                return MISSING_CREDENTIALS_EXIT_CODE

            password_policy = evaluate_bootstrap_password(
                password,
                allow_insecure_password=args.allow_weak_password,
                expected_passwords=expected_passwords,
            )
            if not password_policy.ok:
                acknowledgement_hint = (
                    " or pass --allow-weak-password to acknowledge them"
                    if not args.allow_weak_password
                    else ""
                )
                print(
                    f"ERROR: {password_policy.message or 'Root password is not allowed.'} "
                    f"Choose a password without warnings{acknowledgement_hint}.",
                    file=sys.stderr,
                )
                return MISSING_CREDENTIALS_EXIT_CODE

            try:
                created = await pers.create_verified_root_user_if_empty(
                    email=email_for_storage,
                    password=password,
                    username=username or None,
                    allow_insecure_password=args.allow_weak_password,
                )
            except (HTTPException, ValueError) as exc:
                print(
                    f"ERROR: {getattr(exc, 'detail', exc)}",
                    file=sys.stderr,
                )
                return MISSING_CREDENTIALS_EXIT_CODE
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
