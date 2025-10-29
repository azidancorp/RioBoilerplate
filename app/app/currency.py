"""
Helpers for working with the application's primary currency.

Balances are stored as integers in "minor units" (e.g. cents) to avoid floating
point drift. Use the helpers in this module to convert to/from display values,
format strings, and read the configured naming.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP, getcontext
from typing import Optional

from app.config import config

# Increase precision to safely handle currency conversions (up to 12 decimals).
getcontext().prec = 28


@dataclass(frozen=True)
class CurrencyConfig:
    """Snapshot of currency metadata loaded from AppConfig/environment."""

    name: str
    name_plural: str
    symbol: str
    decimal_places: int
    initial_balance: int
    allow_negative: bool

    def display_name(self, quantity: Optional[Decimal | int | float] = None) -> str:
        """
        Return the singular or plural currency label based on quantity.

        Args:
            quantity: Amount in major units used for pluralisation decisions.

        Returns:
            Singular/plural currency name.
        """
        if quantity is None:
            return self.name_plural

        try:
            normalized = Decimal(quantity)
        except Exception:
            normalized = Decimal("0")

        # Consider absolute value when determining plurality.
        if abs(normalized) == 1:
            return self.name
        return self.name_plural


def get_currency_config() -> CurrencyConfig:
    """
    Snapshot `AppConfig` currency fields into an immutable dataclass.

    Decimal places are clamped to a safe range (0-6) to prevent very small
    increments that SQLite integer storage cannot represent efficiently.
    """
    decimal_places = max(0, min(config.PRIMARY_CURRENCY_DECIMAL_PLACES, 6))
    name = (config.PRIMARY_CURRENCY_NAME or "credit").strip()
    name_plural = (config.PRIMARY_CURRENCY_NAME_PLURAL or f"{name}s").strip()
    symbol = config.PRIMARY_CURRENCY_SYMBOL or ""

    return CurrencyConfig(
        name=name or "credit",
        name_plural=name_plural or f"{name}s" or "credits",
        symbol=symbol.strip(),
        decimal_places=decimal_places,
        initial_balance=int(config.PRIMARY_CURRENCY_INITIAL_BALANCE),
        allow_negative=bool(config.PRIMARY_CURRENCY_ALLOW_NEGATIVE),
    )


def format_minor_amount(
    minor_units: int,
    *,
    include_symbol: bool = True,
    thousands_separator: str = ",",
) -> str:
    """
    Convert an integer number of minor units into a human readable string.

    Args:
        minor_units: Amount stored in persistence (integer).
        include_symbol: Whether to prefix the configured symbol.
        thousands_separator: Separator used for the integer portion.

    Returns:
        Formatted string such as "$42.50" or "120 credits".
    """
    cfg = get_currency_config()
    major = get_major_amount(minor_units)
    sign = "-" if major < 0 else ""
    major = abs(major)

    quantized = major.quantize(
        Decimal(f"1.{'0' * cfg.decimal_places}") if cfg.decimal_places else Decimal("1"),
        rounding=ROUND_HALF_UP,
    )

    integer_part, _, fraction_part = f"{quantized:f}".partition(".")
    integer_part = f"{int(integer_part):,}".replace(",", thousands_separator)

    symbol = f"{cfg.symbol}" if include_symbol and cfg.symbol else ""
    separator = "" if not symbol else ""

    if cfg.decimal_places:
        normalized_fraction = fraction_part.ljust(cfg.decimal_places, "0")
        formatted = f"{sign}{symbol}{separator}{integer_part}.{normalized_fraction}"
    else:
        formatted = f"{sign}{symbol}{separator}{integer_part}"
    return formatted


def get_major_amount(minor_units: int) -> Decimal:
    """
    Convert minor units into a Decimal representing major units.
    """
    cfg = get_currency_config()
    divisor = Decimal(10) ** cfg.decimal_places
    return Decimal(minor_units) / divisor


def major_to_minor(major_amount: Decimal | float | str | int) -> int:
    """
    Convert a major unit value into minor units for persistence.
    """
    cfg = get_currency_config()
    quantize_exp = Decimal(10) ** (-cfg.decimal_places)
    try:
        amount = Decimal(str(major_amount))
    except Exception as exc:  # pragma: no cover - validation catches earlier
        raise ValueError("Invalid amount") from exc

    normalized = amount.quantize(quantize_exp, rounding=ROUND_HALF_UP)
    minor = int(normalized * (Decimal(10) ** cfg.decimal_places))
    return minor


def attach_currency_name(formatted_amount: str, *, quantity_minor_units: int) -> str:
    """
    Append the correct singular/plural currency label to a formatted amount.
    """
    cfg = get_currency_config()
    quantity_major = get_major_amount(quantity_minor_units)
    label = cfg.display_name(quantity_major)
    return f"{formatted_amount} {label}".strip()
