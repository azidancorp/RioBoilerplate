#!/usr/bin/env python3
"""Utility CLI for inspecting and adjusting user currency balances."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from decimal import Decimal
from typing import Iterable
import uuid

from app.currency import (
    attach_currency_name,
    format_minor_amount,
    get_currency_config,
    get_major_amount,
    major_to_minor,
)
from app.data_models import AppUser
from app.persistence import Persistence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Primary currency administration helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List users and their balances")
    list_parser.add_argument("--limit", type=int, default=20, help="Number of users to display")

    ledger_parser = subparsers.add_parser("ledger", help="Show a user's ledger entries")
    ledger_parser.add_argument("identifier", help="User email, username, or ID")
    ledger_parser.add_argument("--limit", type=int, default=20, help="Number of entries to display")

    adjust_parser = subparsers.add_parser("adjust", help="Adjust a balance by a delta amount")
    adjust_parser.add_argument("identifier", help="User email, username, or ID")
    adjust_parser.add_argument("amount", help="Delta amount in major units (positive or negative)")
    adjust_parser.add_argument("--reason", default=None, help="Reason for the ledger entry")

    set_parser = subparsers.add_parser("set", help="Set the balance to an absolute amount")
    set_parser.add_argument("identifier", help="User email, username, or ID")
    set_parser.add_argument("amount", help="Target balance in major units")
    set_parser.add_argument("--reason", default=None, help="Reason for the ledger entry")

    return parser


async def _get_user_by_identifier(pers: Persistence, identifier: str) -> AppUser:
    try:
        return await pers.get_user_by_id(uuid.UUID(identifier))
    except (ValueError, KeyError):
        pass

    try:
        return await pers.get_user_by_email_or_username(identifier)
    except KeyError as exc:
        raise SystemExit(f"User not found: {identifier}") from exc


async def cmd_list(args: argparse.Namespace) -> None:
    pers = Persistence()
    try:
        users = await pers.list_users()
    finally:
        pers.close()

    cfg = get_currency_config()
    print(f"Listing up to {args.limit} users (currency: {cfg.name_plural})")
    print("-" * 72)
    for user in users[: args.limit]:
        balance_text = attach_currency_name(
            format_minor_amount(user.primary_currency_balance),
            quantity_minor_units=user.primary_currency_balance,
        )
        print(f"{user.email:<32} | {user.role:<10} | {balance_text}")


async def cmd_ledger(args: argparse.Namespace) -> None:
    pers = Persistence()
    try:
        user = await _get_user_by_identifier(pers, args.identifier)
        entries = await pers.list_currency_ledger(user.id, limit=args.limit)
    finally:
        pers.close()

    print(f"Ledger for {user.email} ({len(entries)} entries)")
    print("-" * 72)
    for entry in entries:
        delta_text = attach_currency_name(
            format_minor_amount(entry.delta),
            quantity_minor_units=entry.delta,
        )
        balance_text = attach_currency_name(
            format_minor_amount(entry.balance_after),
            quantity_minor_units=entry.balance_after,
        )
        timestamp = entry.created_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        metadata = json.dumps(entry.metadata) if entry.metadata else "{}"
        print(
            f"{timestamp} | delta={delta_text:<18} | balance={balance_text:<18} | reason={entry.reason or ''} | metadata={metadata}"
        )


async def cmd_adjust(args: argparse.Namespace, *, set_mode: bool = False) -> None:
    try:
        amount_decimal = Decimal(args.amount)
    except Exception as exc:
        raise SystemExit(f"Invalid amount: {args.amount}") from exc

    pers = Persistence()
    try:
        user = await _get_user_by_identifier(pers, args.identifier)
        minor_amount = major_to_minor(amount_decimal)
        if set_mode:
            entry = await pers.set_currency_balance(
                user.id,
                new_balance_minor=minor_amount,
                reason=args.reason,
                metadata={"source": "currency_admin_cli"},
                actor_user_id=None,
            )
        else:
            entry = await pers.adjust_currency_balance(
                user.id,
                delta_minor=minor_amount,
                reason=args.reason,
                metadata={"source": "currency_admin_cli"},
                actor_user_id=None,
            )
    finally:
        pers.close()

    delta_text = attach_currency_name(
        format_minor_amount(entry.delta), quantity_minor_units=entry.delta
    )
    balance_text = attach_currency_name(
        format_minor_amount(entry.balance_after), quantity_minor_units=entry.balance_after
    )

    verb = "Set" if set_mode else "Adjusted"
    print(f"{verb} {user.email}'s balance. Delta: {delta_text}. New balance: {balance_text}.")


async def main_async(argv: Iterable[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        await cmd_list(args)
    elif args.command == "ledger":
        await cmd_ledger(args)
    elif args.command == "adjust":
        await cmd_adjust(args, set_mode=False)
    elif args.command == "set":
        await cmd_adjust(args, set_mode=True)
    else:
        parser.error(f"Unknown command: {args.command}")


def main(argv: Iterable[str] | None = None) -> None:
    asyncio.run(main_async(argv))


if __name__ == "__main__":
    main()
