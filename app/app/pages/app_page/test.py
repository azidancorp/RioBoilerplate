from __future__ import annotations

from dataclasses import field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import partial
import json
import typing as t
from uuid import UUID

import rio
from fastapi import HTTPException

from app.api.currency import (
    adjust_currency_route,
    get_currency_balance_route,
    get_currency_config_route,
    list_currency_ledger_route,
    set_currency_route,
)
from app.components.currency_summary import CurrencySummary, CurrencyOverview
from app.data_models import AppUser
from app.persistence import Persistence
from app.validation import (
    CurrencyAdjustmentRequest,
    CurrencyBalanceResponse,
    CurrencyConfigResponse,
    CurrencyLedgerEntryResponse,
    CurrencySetBalanceRequest,
)

TARGET_OPTIONS: dict[str, str] = {
    "Current session user": "current",
    "Explicit user UUID": "uuid",
    "Email or username lookup": "identifier",
}

QUICK_BUY_PACKAGES: tuple[tuple[str, Decimal, str], ...] = (
    ("Buy 10 credits", Decimal("10"), "QA quick purchase"),
    ("Buy 50 credits", Decimal("50"), "QA quick purchase"),
    ("Buy 250 credits", Decimal("250"), "QA quick purchase"),
)

QUICK_SPEND_PACKAGES: tuple[tuple[str, Decimal, str], ...] = (
    ("Spend 5 credits", Decimal("-5"), "QA quick spend"),
    ("Spend 25 credits", Decimal("-25"), "QA quick spend"),
    ("Spend 100 credits", Decimal("-100"), "QA quick spend"),
)


def _chunked(iterable: t.Sequence[rio.Component], size: int) -> list[list[rio.Component]]:
    return [
        list(iterable[index : index + size])
        for index in range(0, len(iterable), size)
    ]


class CurrencyStatePanel(rio.Component):
    config: CurrencyConfigResponse | None = None
    balance: CurrencyBalanceResponse | None = None
    ledger_entries: list[CurrencyLedgerEntryResponse] = field(default_factory=list)
    last_endpoint: str = ""
    last_response_json: str = ""
    is_loading: bool = False
    current_user: AppUser | None = None

    def build(self) -> rio.Component:
        header_rows: list[rio.Component] = []
        if self.current_user:
            header_rows.append(
                rio.Text(
                    f"Acting as: {self.current_user.email} ({self.current_user.role})",
                    style="heading3",
                )
            )
            header_rows.append(
                rio.Text(
                    f"User ID: {self.current_user.id}",
                    style="dim",
                )
            )
        else:
            header_rows.append(
                rio.Text("No authenticated user attached", style="danger")
            )

        config_card = (
            rio.Card(
                rio.Column(
                    rio.Text("Currency Configuration", style="heading3"),
                    rio.Text(f"Name: {self.config.name} / {self.config.name_plural}"),
                    rio.Text(f"Symbol: {self.config.symbol or '—'}"),
                    rio.Text(f"Decimal places: {self.config.decimal_places}"),
                    rio.Text(
                        f"Negative balances allowed: {'Yes' if self.config.allow_negative else 'No'}"
                    ),
                    spacing=0.3,
                ),
                color="hud",
            )
            if self.config
            else rio.Card(
                rio.Text("Config not loaded yet", style="dim"),
                color="hud",
            )
        )

        balance_card: rio.Component
        if self.balance:
            updated_at = (
                datetime.fromtimestamp(self.balance.updated_at, tz=timezone.utc)
                if self.balance.updated_at is not None
                else None
            )
            balance_card = CurrencySummary(
                overview=CurrencyOverview(
                    balance_minor=self.balance.balance_minor,
                    updated_at=updated_at,
                ),
                title="Latest Balance",
            )
        else:
            balance_card = rio.Card(
                rio.Text("Balance not loaded yet", style="dim"),
                color="hud",
            )

        ledger_section: list[rio.Component]
        if self.ledger_entries:
            ledger_cards: list[rio.Component] = []
            for entry in self.ledger_entries:
                timestamp = datetime.fromtimestamp(
                    entry.created_at, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC")
                metadata_text = (
                    json.dumps(entry.metadata, indent=2, default=str)
                    if entry.metadata
                    else "{}"
                )
                ledger_cards.append(
                    rio.Card(
                        rio.Column(
                            rio.Text(
                                f"Δ {entry.delta_with_label}",
                                style="heading3",
                            ),
                            rio.Text(
                                f"Balance after: {entry.balance_after_with_label}"
                            ),
                            rio.Text(f"Reason: {entry.reason or '—'}", style="dim"),
                            rio.Text(f"Metadata: {metadata_text}", style="dim"),
                            rio.Text(f"Actor: {entry.actor_user_id or 'system'}"),
                            rio.Text(f"Created: {timestamp}", style="dim"),
                            spacing=0.3,
                        ),
                        color="hud",
                    )
                )
            ledger_section = [
                rio.Text(
                    f"Ledger Entries ({len(self.ledger_entries)})", style="heading3"
                ),
                rio.ScrollContainer(
                    rio.Column(
                        *ledger_cards,
                        spacing=0.5,
                        grow_y=True,
                    ),
                    min_height=40,
                ),
            ]
        else:
            ledger_section = [
                rio.Text("Ledger entries not loaded yet", style="dim"),
            ]

        response_section = rio.Card(
            rio.Column(
                rio.Text("Last API Response", style="heading3"),
                rio.Text(f"Endpoint: {self.last_endpoint or '—'}", style="dim"),
                rio.ScrollContainer(
                    rio.Text(self.last_response_json or "No response recorded yet"),
                    min_height=10,
                ),
                spacing=0.5,
            ),
            color="hud",
        )

        loading_indicator = (
            rio.Text("Loading…", style="dim") if self.is_loading else rio.Spacer()
        )

        return rio.Column(
            *header_rows,
            config_card,
            balance_card,
            *ledger_section,
            response_section,
            loading_indicator,
            spacing=1,
            margin=1,
        )


@rio.page(
    name="Test",
    url_segment="test",
)
class CurrencyTestHarness(rio.Component):
    config: CurrencyConfigResponse | None = None
    balance: CurrencyBalanceResponse | None = None
    ledger_entries: list[CurrencyLedgerEntryResponse] = field(default_factory=list)

    last_success: str = ""
    last_error: str = ""
    last_endpoint: str = ""
    last_response_json: str = ""
    is_loading: bool = False

    ledger_limit: str = "25"
    manual_amount: str = "10"
    manual_reason: str = ""
    manual_metadata: str = ""

    set_amount: str = ""
    set_reason: str = ""
    set_metadata: str = ""

    target_mode: str = "current"
    target_value: str = ""

    @rio.event.on_populate
    async def on_populate(self) -> None:
        await self._load_config(announce=False, with_loading=False)
        await self._load_balance(announce=False, with_loading=False)
        await self._load_ledger(announce=False, with_loading=False)

    async def _load_config(
        self,
        _: t.Any = None,
        *,
        announce: bool = True,
        with_loading: bool = True,
    ) -> None:
        if with_loading:
            self.is_loading = True
            self.force_refresh()
        try:
            response = await get_currency_config_route()
            self.config = response
            if announce:
                self._record_success(
                    endpoint="GET /api/currency/config",
                    payload=response,
                    message="Currency configuration loaded",
                )
        except Exception as exc:  # pragma: no cover - manual QA tool
            if announce:
                self._record_error("GET /api/currency/config", str(exc))
        finally:
            if with_loading:
                self.is_loading = False
                self.force_refresh()

    async def _load_balance(
        self,
        _: t.Any = None,
        *,
        announce: bool = True,
        with_loading: bool = True,
    ) -> None:
        context = self._require_context()
        if context is None:
            return
        current_user, persistence = context
        if with_loading:
            self.is_loading = True
            self.force_refresh()
        try:
            response = await get_currency_balance_route(
                current_user=current_user,
                db=persistence,
            )
            self.balance = response
            if announce:
                self._record_success(
                    endpoint="GET /api/currency/balance",
                    payload=response,
                    message="Balance fetched",
                )
        except HTTPException as exc:
            if announce:
                self._record_error("GET /api/currency/balance", exc.detail)
        except Exception as exc:  # pragma: no cover - manual QA tool
            if announce:
                self._record_error("GET /api/currency/balance", str(exc))
        finally:
            if with_loading:
                self.is_loading = False
                self.force_refresh()

    async def _load_ledger(
        self,
        _: t.Any = None,
        *,
        announce: bool = True,
        with_loading: bool = True,
    ) -> None:
        context = self._require_context()
        if context is None:
            return
        current_user, persistence = context
        try:
            limit_val = max(1, min(500, int(self.ledger_limit)))
        except (TypeError, ValueError):
            self._record_input_error("Ledger limit must be a number between 1 and 500.")
            return

        try:
            target_id = await self._resolve_target_user_id(persistence, current_user)
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        if with_loading:
            self.is_loading = True
            self.force_refresh()
        try:
            response = await list_currency_ledger_route(
                limit=limit_val,
                before=None,
                after=None,
                user_id=UUID(target_id),
                current_user=current_user,
                db=persistence,
            )
            self.ledger_entries = list(response)
            if announce:
                self._record_success(
                    endpoint="GET /api/currency/ledger",
                    payload=response,
                    message=f"Loaded {len(response)} ledger entries",
                )
        except HTTPException as exc:
            if announce:
                self._record_error("GET /api/currency/ledger", exc.detail)
        except Exception as exc:  # pragma: no cover - manual QA tool
            if announce:
                self._record_error("GET /api/currency/ledger", str(exc))
        finally:
            if with_loading:
                self.is_loading = False
                self.force_refresh()

    async def _quick_adjust(
        self,
        delta: Decimal,
        reason: str,
        _: t.Any = None,
    ) -> None:
        context = self._require_context()
        if context is None:
            return
        current_user, persistence = context
        try:
            target_kwargs = await self._build_target_for_mutation(
                persistence, current_user
            )
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        payload = CurrencyAdjustmentRequest(
            amount=delta,
            reason=reason,
            metadata={"source": "currency-test-harness"},
            **target_kwargs,
        )
        await self._execute_adjustment(
            payload,
            current_user,
            persistence,
            success_label=f"Adjustment applied ({payload.amount} units)",
        )

    async def _submit_adjustment(
        self,
        _: t.Any = None,
    ) -> None:
        context = self._require_context()
        if context is None:
            return
        current_user, persistence = context
        try:
            amount = self._parse_decimal(self.manual_amount)
        except InvalidOperation:
            self._record_input_error("Adjustment amount must be a valid number.")
            return

        if amount == 0:
            self._record_input_error("Adjustment amount must be non-zero.")
            return

        try:
            metadata = self._parse_metadata(self.manual_metadata)
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        try:
            target_kwargs = await self._build_target_for_mutation(
                persistence, current_user
            )
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        payload = CurrencyAdjustmentRequest(
            amount=amount,
            reason=self.manual_reason or None,
            metadata=metadata,
            **target_kwargs,
        )
        await self._execute_adjustment(
            payload,
            current_user,
            persistence,
            success_label=f"Adjusted balance by {payload.amount}",
        )

    async def _submit_set_balance(
        self,
        _: t.Any = None,
    ) -> None:
        context = self._require_context()
        if context is None:
            return
        current_user, persistence = context
        try:
            amount = self._parse_decimal(self.set_amount)
        except InvalidOperation:
            self._record_input_error("Target balance must be a valid number.")
            return

        try:
            metadata = self._parse_metadata(self.set_metadata)
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        try:
            target_kwargs = await self._build_target_for_mutation(
                persistence, current_user
            )
        except ValueError as exc:
            self._record_input_error(str(exc))
            return

        payload = CurrencySetBalanceRequest(
            balance=amount,
            reason=self.set_reason or None,
            metadata=metadata,
            **target_kwargs,
        )
        await self._execute_set_balance(
            payload,
            current_user,
            persistence,
            success_label=f"Set balance to {payload.balance}",
        )

    async def _execute_adjustment(
        self,
        payload: CurrencyAdjustmentRequest,
        current_user: AppUser,
        persistence: Persistence,
        *,
        success_label: str,
    ) -> None:
        self.is_loading = True
        self.force_refresh()
        try:
            response = await adjust_currency_route(
                payload=payload,
                current_user=current_user,
                db=persistence,
            )
            self._record_success(
                endpoint="POST /api/currency/adjust",
                payload=response,
                message=success_label,
            )
            await self._refresh_after_mutation()
        except HTTPException as exc:
            self._record_error("POST /api/currency/adjust", exc.detail)
        except Exception as exc:  # pragma: no cover - manual QA tool
            self._record_error("POST /api/currency/adjust", str(exc))
        finally:
            self.is_loading = False
            self.force_refresh()

    async def _execute_set_balance(
        self,
        payload: CurrencySetBalanceRequest,
        current_user: AppUser,
        persistence: Persistence,
        *,
        success_label: str,
    ) -> None:
        self.is_loading = True
        self.force_refresh()
        try:
            response = await set_currency_route(
                payload=payload,
                current_user=current_user,
                db=persistence,
            )
            self._record_success(
                endpoint="POST /api/currency/set",
                payload=response,
                message=success_label,
            )
            await self._refresh_after_mutation()
        except HTTPException as exc:
            self._record_error("POST /api/currency/set", exc.detail)
        except Exception as exc:  # pragma: no cover - manual QA tool
            self._record_error("POST /api/currency/set", str(exc))
        finally:
            self.is_loading = False
            self.force_refresh()

    async def _refresh_after_mutation(self) -> None:
        await self._load_balance(announce=False, with_loading=False)
        await self._load_ledger(announce=False, with_loading=False)

    def _record_success(self, *, endpoint: str, payload: t.Any, message: str) -> None:
        self.last_success = message
        self.last_error = ""
        self.last_endpoint = endpoint
        self.last_response_json = self._stringify_payload(payload)
        self.force_refresh()

    def _record_error(self, endpoint: str, detail: t.Any) -> None:
        detail_text = detail if isinstance(detail, str) else str(detail)
        self.last_error = f"{endpoint} failed: {detail_text}"
        self.last_success = ""
        self.last_endpoint = endpoint
        self.last_response_json = self._stringify_payload({"error": detail_text})
        self.force_refresh()

    def _record_input_error(self, message: str) -> None:
        self.last_error = message
        self.last_success = ""
        self.force_refresh()

    def _parse_decimal(self, raw: str) -> Decimal:
        text = (raw or "").strip()
        if not text:
            raise InvalidOperation("blank amount")
        return Decimal(text)

    def _parse_metadata(self, raw: str) -> dict[str, t.Any] | None:
        text = (raw or "").strip()
        if not text:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Metadata must be valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("Metadata must be a JSON object.")
        return data

    def _stringify_payload(self, payload: t.Any) -> str:
        normalized = self._normalize_payload(payload)
        try:
            return json.dumps(normalized, indent=2, default=str)
        except TypeError:
            return str(normalized)

    def _normalize_payload(self, payload: t.Any) -> t.Any:
        if hasattr(payload, "model_dump"):
            return payload.model_dump()
        if isinstance(payload, list):
            return [self._normalize_payload(item) for item in payload]
        if isinstance(payload, dict):
            return {key: self._normalize_payload(value) for key, value in payload.items()}
        return payload

    def _require_context(self) -> tuple[AppUser, Persistence] | None:
        try:
            current_user = self.session[AppUser]
        except KeyError:
            self._record_input_error("Log in to exercise the currency API endpoints.")
            return None
        persistence = self.session[Persistence]
        return current_user, persistence

    async def _build_target_for_mutation(
        self,
        persistence: Persistence,
        current_user: AppUser,
    ) -> dict[str, str]:
        if self.target_mode == "current":
            return {"target_user_id": str(current_user.id)}

        candidate = (self.target_value or "").strip()
        if not candidate:
            raise ValueError("Enter a target UUID or identifier first.")

        if self.target_mode == "uuid":
            try:
                UUID(candidate)
            except ValueError as exc:
                raise ValueError("Target UUID is invalid.") from exc
            return {"target_user_id": candidate}

        return {"target_identifier": candidate}

    async def _resolve_target_user_id(
        self,
        persistence: Persistence,
        current_user: AppUser,
    ) -> str:
        if self.target_mode == "current":
            return str(current_user.id)

        candidate = (self.target_value or "").strip()
        if not candidate:
            raise ValueError("Enter a target before loading the ledger.")

        if self.target_mode == "uuid":
            try:
                return str(UUID(candidate))
            except ValueError as exc:
                raise ValueError("Target UUID is invalid.") from exc

        try:
            user = await persistence.get_user_by_email_or_username(candidate)
        except KeyError as exc:
            raise ValueError(f"User not found for identifier: {candidate}") from exc
        return str(user.id)

    def _current_user_optional(self) -> AppUser | None:
        try:
            return self.session[AppUser]
        except KeyError:
            return None

    def _current_user_label(self) -> str:
        user = self._current_user_optional()
        if not user:
            return "Not authenticated"
        return f"{user.email} ({user.role})"

    def build(self) -> rio.Component:
        status_banner: rio.Component
        if self.last_error:
            status_banner = rio.Banner(text=self.last_error, style="danger")
        elif self.last_success:
            status_banner = rio.Banner(text=self.last_success, style="success")
        else:
            status_banner = rio.Spacer()

        target_description_map = {
            "current": "Requests operate on the logged-in user.",
            "uuid": "Requests include the UUID provided below.",
            "identifier": "Adjust/Set use the identifier; ledger resolves it to a UUID first.",
        }

        quick_buy_buttons = [
            rio.Button(
                label,
                on_press=partial(self._quick_adjust, amount, reason),
                shape="rounded",
            )
            for label, amount, reason in QUICK_BUY_PACKAGES
        ]

        quick_spend_buttons = [
            rio.Button(
                label,
                on_press=partial(self._quick_adjust, amount, reason),
                shape="rounded",
            )
            for label, amount, reason in QUICK_SPEND_PACKAGES
        ]

        quick_reset_buttons = [
            rio.Button(
                "Set balance to zero",
                on_press=partial(
                    self._submit_set_balance_with_amount,
                    Decimal("0"),
                    "QA zero reset",
                ),
                shape="rounded",
            ),
            rio.Button(
                "Set balance to 1,000",
                on_press=partial(
                    self._submit_set_balance_with_amount,
                    Decimal("1000"),
                    "QA bulk load",
                ),
                shape="rounded",
            ),
        ]

        target_controls: list[rio.Component] = [
            rio.Text("Target selection", style="heading3"),
            rio.Dropdown(
                label="Operate on",
                options=TARGET_OPTIONS,
                selected_value=self.bind().target_mode,
            ),
            rio.Text(target_description_map[self.target_mode], style="dim"),
        ]

        if self.target_mode != "current":
            target_controls.append(
                rio.TextInput(
                    label="Target value",
                    text=self.bind().target_value,
                )
            )

        target_controls.append(
            rio.Text(f"Current user: {self._current_user_label()}", style="dim"),
        )

        quick_actions_section: list[rio.Component] = [
            rio.Text("Quick purchase buttons", style="heading3"),
        ]
        for row in _chunked(quick_buy_buttons, 2):
            quick_actions_section.append(rio.Row(*row, spacing=1))

        quick_actions_section.append(
            rio.Text("Quick spend buttons", style="heading3"),
        )
        for row in _chunked(quick_spend_buttons, 2):
            quick_actions_section.append(rio.Row(*row, spacing=1))

        quick_actions_section.append(
            rio.Text("Quick balance presets", style="heading3"),
        )
        for row in _chunked(quick_reset_buttons, 2):
            quick_actions_section.append(rio.Row(*row, spacing=1))

        manual_adjust_section = rio.Card(
            rio.Column(
                rio.Text("Manual Adjustment", style="heading3"),
                rio.TextInput(
                    label="Delta amount (major units)",
                    text=self.bind().manual_amount,
                ),
                rio.TextInput(
                    label="Reason",
                    text=self.bind().manual_reason,
                ),
                rio.MultiLineTextInput(
                    label="Metadata (JSON object)",
                    text=self.bind().manual_metadata,
                    min_height=3,
                ),
                rio.Button(
                    "POST /api/currency/adjust",
                    on_press=self._submit_adjustment,
                    shape="rounded",
                ),
                spacing=0.7,
            ),
            margin=0.5,
        )

        manual_set_section = rio.Card(
            rio.Column(
                rio.Text("Set Absolute Balance", style="heading3"),
                rio.TextInput(
                    label="Target balance (major units)",
                    text=self.bind().set_amount,
                ),
                rio.TextInput(
                    label="Reason",
                    text=self.bind().set_reason,
                ),
                rio.MultiLineTextInput(
                    label="Metadata (JSON object)",
                    text=self.bind().set_metadata,
                    min_height=3,
                ),
                rio.Button(
                    "POST /api/currency/set",
                    on_press=self._submit_set_balance,
                    shape="rounded",
                ),
                spacing=0.7,
            ),
            margin=0.5,
        )

        loader_controls = rio.Card(
            rio.Column(
                rio.Text("Data fetchers", style="heading3"),
                rio.Button(
                    "GET /api/currency/config",
                    on_press=self._load_config,
                    shape="rounded",
                ),
                rio.Button(
                    "GET /api/currency/balance",
                    on_press=self._load_balance,
                    shape="rounded",
                ),
                rio.Row(
                    rio.TextInput(
                        label="Ledger limit (1-500)",
                        text=self.bind().ledger_limit,
                        min_width=10,
                    ),
                    rio.Button(
                        "GET /api/currency/ledger",
                        on_press=self._load_ledger,
                        shape="rounded",
                    ),
                    spacing=1,
                ),
                spacing=0.7,
            ),
            margin=0.5,
        )

        control_column = rio.Column(
            status_banner,
            rio.Card(
                rio.Column(*target_controls, spacing=0.6),
                margin=0.5,
            ),
            loader_controls,
            rio.Card(
                rio.Column(*quick_actions_section, spacing=0.6),
                margin=0.5,
            ),
            manual_adjust_section,
            manual_set_section,
            spacing=1,
            min_width=28,
        )

        state_panel = CurrencyStatePanel(
            config=self.config,
            balance=self.balance,
            ledger_entries=self.ledger_entries,
            last_endpoint=self.last_endpoint,
            last_response_json=self.last_response_json,
            is_loading=self.is_loading,
            current_user=self._current_user_optional(),
        )

        return rio.Column(
            rio.Text("Currency QA Playground", style="heading1"),
            rio.Text(
                "Use these manual controls to exercise every currency API endpoint.",
                style="dim",
            ),
            rio.Row(
                control_column,
                rio.Separator(),
                state_panel,
                spacing=1.5,
                align_y=0,
                grow_x=True,
                proportions=[10,1,10],
            ),
            spacing=1,
            margin=2,
        )

    async def _submit_set_balance_with_amount(
        self,
        amount: Decimal,
        reason: str,
        _: t.Any = None,
    ) -> None:
        self.set_amount = str(amount)
        self.set_reason = reason
        await self._submit_set_balance()
