from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import rio

from app.currency import (
    attach_currency_name,
    format_minor_amount,
    get_major_amount,
)


@dataclass
class CurrencyOverview:
    """Lightweight container used by CurrencySummary component."""

    balance_minor: int
    updated_at: Optional[datetime] = None

    @property
    def formatted(self) -> str:
        return format_minor_amount(self.balance_minor)

    @property
    def formatted_with_label(self) -> str:
        return attach_currency_name(self.formatted, quantity_minor_units=self.balance_minor)

    @property
    def balance_major(self) -> float:
        return float(get_major_amount(self.balance_minor))


class CurrencySummary(rio.Component):
    """
    Display component that presents the user's current currency balance with context.
    """

    overview: CurrencyOverview
    title: str = "Account Balance"
    show_timestamp: bool = True

    def build(self) -> rio.Component:
        subtitled_rows = []
        if self.show_timestamp:
            updated_at_text = (
                self.overview.updated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                if self.overview.updated_at
                else "Never updated"
            )
            subtitled_rows.append(
                rio.Text(
                    f"Last updated: {updated_at_text}",
                    style="dim",
                )
            )

        return rio.Card(
            rio.Column(
                rio.Text(self.title, style="heading3"),
                rio.Text(
                    self.overview.formatted_with_label,
                    style="heading1",
                ),
                *subtitled_rows,
                spacing=0.5,
            ),
            margin=0.5,
        )
