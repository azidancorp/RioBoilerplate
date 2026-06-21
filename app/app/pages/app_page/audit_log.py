from __future__ import annotations

from dataclasses import field
import typing as t

import pandas as pd
import rio

from app.data_models import AppUser
from app.permissions import check_access
from app.persistence import Persistence
from app.session_validation import refresh_attached_user_session, reject_stale_user_session
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_FULL


@rio.page(
    name="AuditLogPage",
    url_segment="audit-log",
)
class AuditLogPage(ResponsiveComponent):
    """Read-only viewer for the admin action audit log.

    Renders ``Persistence.list_admin_actions`` newest-first. Access is gated to
    the same roles as the admin page via the ``/app/audit-log`` mapping in
    ``navigation.APP_ROUTES`` (a flat segment so the ``/app/`` guard resolves it
    — see app_page.py).
    """

    current_user: AppUser | None = None
    df: pd.DataFrame | None = None

    # Optional filters.
    filter_action: str = ""
    filter_actor_id: str = ""
    filter_target_id: str = ""

    @rio.event.on_populate
    async def on_populate(self) -> None:
        await self._load_audit_data()

    def _refresh_current_user_authorization(self) -> bool:
        try:
            user_session, current_user = refresh_attached_user_session(self.session)
        except KeyError:
            self.current_user = None
            self.df = pd.DataFrame([])
            reject_stale_user_session(self.session)
            return False

        if not check_access("/app/audit-log", current_user.role):
            self.current_user = None
            self.df = pd.DataFrame([])
            self.session.attach(user_session)
            self.session.attach(current_user)
            self.session.navigate_to("/")
            return False

        self.session.attach(user_session)
        self.session.attach(current_user)
        self.current_user = current_user
        return True

    @staticmethod
    def _parse_uuid(value: str):
        import uuid

        value = (value or "").strip()
        if not value:
            return None
        try:
            return uuid.UUID(value)
        except ValueError:
            return None

    async def _load_audit_data(self) -> None:
        if not self._refresh_current_user_authorization():
            return

        persistence = self.session[Persistence]
        rows = persistence.list_admin_actions(
            action=(self.filter_action or "").strip() or None,
            actor_user_id=self._parse_uuid(self.filter_actor_id),
            target_user_id=self._parse_uuid(self.filter_target_id),
            limit=200,
        )

        data: list[dict[str, t.Any]] = []
        for row in rows:
            data.append(
                {
                    "When": row["created_at"].strftime("%Y-%m-%d %H:%M:%S"),
                    "Action": row["action"],
                    "Outcome": row["outcome"],
                    "Actor": str(row["actor_user_id"] or ""),
                    "Actor Role": row["actor_role"] or "",
                    "Target": row["target_label"] or str(row["target_user_id"] or ""),
                    "Before": "" if row["before"] is None else str(row["before"]),
                    "After": "" if row["after"] is None else str(row["after"]),
                    "Source IP": row["client_ip"] or "",
                }
            )

        self.df = pd.DataFrame(data)

    async def _on_apply_filters(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        await self._load_audit_data()
        self.force_refresh()

    def build(self) -> rio.Component:
        if not self.current_user or self.df is None:
            return rio.Text("Error: Could not load audit log")

        table: rio.Component
        if self.df.empty:
            table = rio.Text("No audit entries match the current filters.")
        else:
            table = rio.ScrollContainer(
                rio.Table(
                    data=self.df,
                    show_row_numbers=False,
                    min_height=20,
                ),
                scroll_x="auto",
                scroll_y="auto",
                min_height=20,
            )

        return CenterComponent(
            rio.Column(
                rio.Text(
                    "Admin Audit Log",
                    style="heading1",
                    margin_bottom=2,
                    overflow="wrap",
                ),
                rio.Row(
                    rio.TextInput(
                        label="Action (optional)",
                        text=self.bind().filter_action,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.TextInput(
                        label="Actor User ID (optional)",
                        text=self.bind().filter_actor_id,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.TextInput(
                        label="Target User ID (optional)",
                        text=self.bind().filter_target_id,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.Button(
                        "Apply Filters",
                        on_press=self._on_apply_filters,
                        shape="rounded",
                    ),
                    spacing=self.flow_spacing,
                ) if not self.is_mobile else rio.FlowContainer(
                    rio.TextInput(
                        label="Action (optional)",
                        text=self.bind().filter_action,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.TextInput(
                        label="Actor User ID (optional)",
                        text=self.bind().filter_actor_id,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.TextInput(
                        label="Target User ID (optional)",
                        text=self.bind().filter_target_id,
                        on_confirm=self._on_apply_filters,
                    ),
                    rio.Button(
                        "Apply Filters",
                        on_press=self._on_apply_filters,
                        shape="rounded",
                    ),
                    row_spacing=self.flow_spacing,
                    column_spacing=self.flow_spacing,
                ),
                rio.Card(
                    rio.Column(
                        table,
                        margin=2,
                    ),
                    margin_top=2,
                ),
                align_x=0.5,
                margin=self.page_margin,
            ),
            width_percent=WIDTH_FULL,
        )
