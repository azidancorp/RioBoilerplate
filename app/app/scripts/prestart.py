#!/usr/bin/env python3
"""Prestart checks for deployment service managers."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from app.api.health import check_sqlite_health
from app.config import config
from app.persistence import DEFAULT_DB_PATH, Persistence


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
        "--db-path",
        type=Path,
        default=None,
        help="SQLite database path. Defaults to the app runtime database.",
    )
    return parser


def run_prestart(args: argparse.Namespace) -> int:
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
