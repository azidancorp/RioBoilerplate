from __future__ import annotations

from dataclasses import field
from decimal import Decimal, InvalidOperation
import logging
import sqlite3
import uuid
import typing as t
import pandas as pd

import rio
from app.persistence import Persistence
from app.data_models import AppUser, UserSession
from app.permissions import can_manage_role, check_access, get_manageable_roles, get_default_role
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import (
    StepUpResult,
    perform_step_up,
    refresh_attached_user_session,
    reject_stale_user_session,
    require_elevated_session,
    verify_step_up_credentials,
)
from app.currency import major_to_minor, format_minor_amount, attach_currency_name
from app.validation import SecuritySanitizer
from app.scripts.message_utils import send_password_reset_email
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_FULL

logger = logging.getLogger(__name__)

@rio.page(
    name="AdminPage",
    url_segment="admin",
)
class AdminPage(ResponsiveComponent):
    """
    Admin page for managing users and their roles.
    Only accessible to users with admin or root roles.
    """

    # Keep track of users and their current roles
    users: t.List[AppUser] = field(default_factory=list)
    selected_role: t.Dict[str, str] = field(default_factory=dict)
    current_user: AppUser | None = None
    df: pd.DataFrame | None = None

    # User change role fields
    change_role_identifier: str = ""
    change_role_new_role: str = field(default_factory=get_default_role)
    change_role_error: str = ""

    # User creation fields
    create_user_email: str = ""
    create_user_username: str = ""
    create_user_full_name: str = ""
    create_user_password: str = ""
    create_user_role: str = field(default_factory=get_default_role)
    create_user_is_verified: bool = False
    create_user_error: str = ""
    create_user_success: str = ""

    # User profile edit fields
    edit_user_identifier: str = ""
    edit_user_email: str = ""
    edit_user_username: str = ""
    edit_user_full_name: str = ""
    edit_user_error: str = ""
    edit_user_success: str = ""

    # User active-state fields
    active_user_identifier: str = ""
    active_user_is_active: bool = True
    active_user_confirmation: str = ""
    active_user_error: str = ""
    active_user_success: str = ""

    # Password reset fields
    reset_user_identifier: str = ""
    reset_user_error: str = ""
    reset_user_success: str = ""

    # User deletion fields
    delete_user_identifier: str = ""
    delete_user_confirmation: str = ""
    delete_user_step_up_password: str = ""
    delete_user_step_up_2fa: str = ""
    delete_user_error: str = ""
    delete_user_success: str = ""

    # Currency management fields
    currency_user_identifier: str = ""
    currency_amount: str = ""
    currency_reason: str = ""
    currency_mode_is_set: bool = False  # False -> adjust delta, True -> set absolute
    currency_error: str = ""
    currency_success: str = ""

    # Step-up (sudo mode) re-auth dialog state. When a sensitive action (role
    # change) is attempted without an active elevation window, the dialog is
    # shown and the pending action is stashed so it can be replayed on success.
    step_up_visible: bool = False
    step_up_password: str = ""
    step_up_2fa: str = ""
    step_up_error: str = ""
    step_up_pending_identifier: str = ""
    step_up_pending_new_role: str = ""

    @rio.event.on_populate
    async def on_populate(self):
        """Load all users when the page is populated."""
        await self._load_user_data()

    def _clear_user_data(self) -> None:
        self.current_user = None
        self.users = []
        self.selected_role = {}
        self.df = pd.DataFrame([])

    def _reject_stale_auth_session(self) -> None:
        reject_stale_user_session(self.session)

    def _refresh_current_user_authorization(self) -> bool:
        try:
            user_session, current_user = refresh_attached_user_session(self.session)
        except KeyError:
            self._clear_user_data()
            self._reject_stale_auth_session()
            return False

        if not check_access("/app/admin", current_user.role):
            self._clear_user_data()
            self.session.attach(user_session)
            self.session.attach(current_user)
            self.session.navigate_to("/")
            return False

        self.session.attach(user_session)
        self.session.attach(current_user)
        self.current_user = current_user
        return True

    def _check_sensitive_limit(
        self,
        persistence: Persistence,
        scope: str,
        *,
        target: str = "",
    ):
        context = context_from_rio_session(self.session)
        actor = (
            context.user_id
            or (str(self.current_user.id) if self.current_user else "")
            or context.client_ip
        )
        return persistence.check_rate_limit(
            policy=sensitive_action_policy(scope),
            key=rate_limit_key(scope, f"{actor}:{target}"),
        )

    def _client_ip(self) -> str | None:
        """Best-effort source IP for audit attribution."""
        return context_from_rio_session(self.session).client_ip

    async def _get_target_user(self, identifier: str) -> AppUser:
        persistence = self.session[Persistence]
        try:
            return await persistence.get_user_by_id(uuid.UUID(identifier))
        except (ValueError, KeyError):
            return await persistence.get_user_by_email_or_username(identifier)

    def _can_manage_user(self, target_user: AppUser) -> bool:
        if not self.current_user:
            return False
        try:
            return can_manage_role(self.current_user.role, target_user.role)
        except ValueError:
            return False

    def _clear_rate_limit(
        self,
        persistence: Persistence,
        scope: str,
        target: str,
    ) -> None:
        if not self.current_user:
            return
        persistence.clear_rate_limit(
            scope=sensitive_action_policy(scope).scope,
            key=rate_limit_key(scope, f"{self.current_user.id}:{target}"),
        )

    def _clear_delete_step_up_fields(self) -> None:
        self.delete_user_step_up_password = ""
        self.delete_user_step_up_2fa = ""

    async def _verify_actor_step_up(
        self,
        persistence: Persistence,
        *,
        password: str,
        two_factor_code: str | None,
    ) -> StepUpResult:
        if not self.current_user:
            return StepUpResult(
                ok=False,
                error_message="You must be logged in to perform this action",
            )

        decision = self._check_sensitive_limit(persistence, "admin_step_up")
        if not decision.allowed:
            return StepUpResult(
                ok=False,
                error_message=rate_limited_message(
                    "Too many verification attempts.",
                    decision.retry_after_seconds,
                ),
            )

        try:
            user_session = self.session[UserSession]
        except KeyError:
            return StepUpResult(
                ok=False,
                error_message="Your session has expired. Please log in again.",
            )

        result = await verify_step_up_credentials(
            persistence,
            user_session,
            self.current_user,
            password=password,
            two_factor_code=two_factor_code,
        )
        if result.ok:
            self._clear_rate_limit(persistence, "admin_step_up", "")
        return result

    def _admin_error_message(self, action: str, exc: Exception) -> str:
        if isinstance(exc, PermissionError):
            return str(exc)
        if isinstance(exc, ValueError):
            return str(exc)
        if isinstance(exc, sqlite3.IntegrityError):
            message = str(exc)
            if "users.email" in message:
                return "A user with that email already exists."
            if "users.username" in message:
                return "A user with that username already exists."
            if "profiles.email" in message:
                return "A profile with that email already exists."
        logger.exception("Admin error while %s", action)
        return f"Error {action}. Please check the input and try again."

    async def _on_create_user_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            return

        if not self.current_user:
            self.create_user_error = "You must be logged in to perform this action"
            self.create_user_success = ""
            self.force_refresh()
            return

        email = (self.create_user_email or "").strip()
        password = self.create_user_password or ""
        role = (self.create_user_role or "").strip()

        if not email:
            self.create_user_error = "Please enter an email"
            self.create_user_success = ""
            self.force_refresh()
            return

        if len(password.strip()) < 8:
            self.create_user_error = "Password must be at least 8 characters"
            self.create_user_success = ""
            self.force_refresh()
            return

        try:
            can_create_role = can_manage_role(self.current_user.role, role)
        except ValueError:
            can_create_role = False

        if not can_create_role:
            self.create_user_error = (
                f"You do not have permission to create users with role: {role}"
            )
            self.create_user_success = ""
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        decision = self._check_sensitive_limit(
            persistence,
            "admin_create_user",
            target=email,
        )
        if not decision.allowed:
            self.create_user_error = rate_limited_message(
                "Too many user creation attempts.",
                decision.retry_after_seconds,
            )
            self.create_user_success = ""
            self.force_refresh()
            return

        try:
            created = await persistence.admin_create_user(
                email=email,
                password=password,
                role=role,
                actor=self.current_user,
                username=(self.create_user_username or "").strip() or None,
                full_name=(self.create_user_full_name or "").strip() or None,
                is_verified=self.create_user_is_verified,
                client_ip=self._client_ip(),
            )
        except Exception as exc:
            self.create_user_error = self._admin_error_message("creating user", exc)
            self.create_user_success = ""
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_create_user", email)
        self.create_user_success = f"Created user {created.email}"
        self.create_user_error = ""
        self.create_user_email = ""
        self.create_user_username = ""
        self.create_user_full_name = ""
        self.create_user_password = ""
        self.create_user_role = get_default_role()
        self.create_user_is_verified = False
        await self._load_user_data()
        self.force_refresh()

    async def _on_edit_user_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            return

        identifier = (self.edit_user_identifier or "").strip()
        if not identifier:
            self.edit_user_error = "Please enter a user email, username, or ID"
            self.edit_user_success = ""
            self.force_refresh()
            return

        updates = {
            "email": (self.edit_user_email or "").strip() or None,
            "username": (self.edit_user_username or "").strip() or None,
            "full_name": (self.edit_user_full_name or "").strip() or None,
        }
        if not any(updates.values()):
            self.edit_user_error = "Enter at least one field to update"
            self.edit_user_success = ""
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.edit_user_error = f"User not found: {identifier}"
            self.edit_user_success = ""
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.edit_user_error = (
                f"You do not have permission to edit users with role: {target_user.role}"
            )
            self.edit_user_success = ""
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        decision = self._check_sensitive_limit(
            persistence,
            "admin_edit_user",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.edit_user_error = rate_limited_message(
                "Too many user edit attempts.",
                decision.retry_after_seconds,
            )
            self.edit_user_success = ""
            self.force_refresh()
            return

        try:
            updated = await persistence.admin_update_user_profile(
                target_user.id,
                actor=self.current_user,
                email=updates["email"],
                username=updates["username"],
                full_name=updates["full_name"],
                client_ip=self._client_ip(),
            )
        except Exception as exc:
            self.edit_user_error = self._admin_error_message("updating user", exc)
            self.edit_user_success = ""
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_edit_user", str(target_user.id))
        self.edit_user_success = f"Updated user {updated.email}"
        self.edit_user_error = ""
        self.edit_user_identifier = ""
        self.edit_user_email = ""
        self.edit_user_username = ""
        self.edit_user_full_name = ""
        await self._load_user_data()
        self.force_refresh()

    async def _on_set_active_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            return

        identifier = (self.active_user_identifier or "").strip()
        if not identifier:
            self.active_user_error = "Please enter a user email, username, or ID"
            self.active_user_success = ""
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.active_user_error = f"User not found: {identifier}"
            self.active_user_success = ""
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.active_user_error = (
                f"You do not have permission to update users with role: {target_user.role}"
            )
            self.active_user_success = ""
            self.force_refresh()
            return

        if not self.active_user_is_active:
            expected_confirmation = f"DEACTIVATE {target_user.email}"
            if self.active_user_confirmation.strip() != expected_confirmation:
                self.active_user_error = (
                    f'Type "{expected_confirmation}" to confirm deactivation.'
                )
                self.active_user_success = ""
                self.force_refresh()
                return

        persistence = self.session[Persistence]
        decision = self._check_sensitive_limit(
            persistence,
            "admin_set_user_active",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.active_user_error = rate_limited_message(
                "Too many account status attempts.",
                decision.retry_after_seconds,
            )
            self.active_user_success = ""
            self.force_refresh()
            return

        try:
            updated = await persistence.admin_set_user_active(
                target_user.id,
                self.active_user_is_active,
                actor=self.current_user,
                client_ip=self._client_ip(),
            )
        except Exception as exc:
            self.active_user_error = self._admin_error_message(
                "updating account status",
                exc,
            )
            self.active_user_success = ""
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_set_user_active", str(target_user.id))
        status_text = "activated" if updated.is_active else "deactivated"
        self.active_user_success = f"User {updated.email} has been {status_text}"
        self.active_user_error = ""
        self.active_user_identifier = ""
        self.active_user_confirmation = ""
        self.active_user_is_active = True
        await self._load_user_data()
        self.force_refresh()

    async def _on_send_reset_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            return

        identifier = (self.reset_user_identifier or "").strip()
        if not identifier:
            self.reset_user_error = "Please enter a user email, username, or ID"
            self.reset_user_success = ""
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.reset_user_error = f"User not found: {identifier}"
            self.reset_user_success = ""
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.reset_user_error = (
                f"You do not have permission to reset users with role: {target_user.role}"
            )
            self.reset_user_success = ""
            self.force_refresh()
            return

        if not target_user.is_active:
            self.reset_user_error = "Reactivate this user before sending a password reset"
            self.reset_user_success = ""
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        decision = self._check_sensitive_limit(
            persistence,
            "admin_send_password_reset",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.reset_user_error = rate_limited_message(
                "Too many password reset attempts.",
                decision.retry_after_seconds,
            )
            self.reset_user_success = ""
            self.force_refresh()
            return

        try:
            reset_token = await persistence.admin_issue_password_reset(
                target_user.id,
                actor=self.current_user,
                client_ip=self._client_ip(),
            )
            send_password_reset_email(
                recipient=target_user.email,
                token=reset_token.token,
                valid_until=reset_token.valid_until,
            )
        except Exception as exc:
            self.reset_user_error = self._admin_error_message(
                "sending password reset",
                exc,
            )
            self.reset_user_success = ""
            self.force_refresh()
            return

        self._clear_rate_limit(
            persistence,
            "admin_send_password_reset",
            str(target_user.id),
        )
        self.reset_user_success = f"Password reset email sent to {target_user.email}"
        self.reset_user_error = ""
        self.reset_user_identifier = ""
        self.force_refresh()

    async def _load_user_data(self) -> None:
        """Populate component state with the latest user data."""
        if not self._refresh_current_user_authorization():
            return

        persistence = self.session[Persistence]
        self.users = await persistence.list_users()
        self.selected_role = {str(user.id): user.role for user in self.users}

        data = []
        for user in self.users:
            data.append({
                "Email": user.email,
                "Username": user.username or "",
                "Created At": user.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "Role": user.role,
                "Active": "✓" if user.is_active else "✗",
                "Verified": "✓" if user.is_verified else "✗",
                "Balance": attach_currency_name(
                    format_minor_amount(user.primary_currency_balance),
                    quantity_minor_units=user.primary_currency_balance,
                ),
                "ID": str(user.id),
            })

        self.df = pd.DataFrame(data)

    async def _on_change_role_pressed(self) -> None:
        identifier = (self.change_role_identifier or "").strip()
        new_role = (self.change_role_new_role or "").strip()

        if not identifier:
            self.change_role_error = "Please enter an email or username"
            self.force_refresh()
            return

        if not new_role:
            self.change_role_error = "Please enter a new role"
            self.force_refresh()
            return

        updated = await self._update_role(identifier, new_role)
        if updated:
            self.change_role_identifier = ""
            self.change_role_new_role = get_default_role()
            await self._load_user_data()

        self.force_refresh()

    async def _update_role(self, identifier: str, new_role: str) -> bool:
        """Update a user's role."""
        if not self._refresh_current_user_authorization():
            return False

        if not self.current_user:
            self.change_role_error = "You must be logged in to perform this action"
            return False

        persistence = self.session[Persistence]
        try:
            target_user = await persistence.get_user_by_email_or_username(identifier)
        except KeyError:
            self.change_role_error = f"User {identifier} not found"
            return False

        current_role = target_user.role

        try:
            can_manage_target = can_manage_role(self.current_user.role, current_role)
            can_manage_new = can_manage_role(self.current_user.role, new_role)
        except ValueError:
            self.change_role_error = f"Unknown role: {new_role}"
            return False

        # Check if the current user can manage both the user's current and new roles
        if not (can_manage_target and can_manage_new):
            self.change_role_error = (
                f"You do not have permission to change role from {current_role} to "
                f"{new_role} because your role is {self.current_user.role}"
            )
            return False

        # Sudo mode: require a recent step-up re-auth before mutating a role. The
        # gate is re-validated server-side here (not just when the dialog closes),
        # so a stale/expired elevation re-prompts. The action is legitimate at
        # this point (permissions already checked), so prompting is warranted.
        if require_elevated_session(self.session) is None:
            self._show_step_up_dialog(identifier=identifier, new_role=new_role)
            return False

        decision = self._check_sensitive_limit(
            persistence,
            "admin_change_role",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.change_role_error = rate_limited_message(
                "Too many role-change attempts.",
                decision.retry_after_seconds,
            )
            return False

        try:
            self.change_role_error = ""
            await persistence.update_user_role(
                target_user.id,
                new_role,
                actor=self.current_user,
                client_ip=self._client_ip(),
            )
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("admin_change_role").scope,
                key=rate_limit_key("admin_change_role", f"{self.current_user.id}:{target_user.id}"),
            )
            return True
        except Exception as exc:
            self.change_role_error = self._admin_error_message("updating role", exc)
            return False

    def _show_step_up_dialog(self, *, identifier: str, new_role: str) -> None:
        """Stash the pending role change and reveal the step-up re-auth dialog."""
        self.step_up_pending_identifier = identifier
        self.step_up_pending_new_role = new_role
        self.step_up_password = ""
        self.step_up_2fa = ""
        self.step_up_error = ""
        self.step_up_visible = True

    def _hide_step_up_dialog(self) -> None:
        self.step_up_visible = False
        self.step_up_password = ""
        self.step_up_2fa = ""
        self.step_up_error = ""
        self.step_up_pending_identifier = ""
        self.step_up_pending_new_role = ""

    def _on_step_up_cancel(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        self._hide_step_up_dialog()
        self.force_refresh()

    async def _on_step_up_submit(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Verify the admin's own credentials, elevate, and replay the role change."""
        if not self._refresh_current_user_authorization():
            return

        if not self.current_user:
            self.step_up_error = "You must be logged in to perform this action"
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        # Throttle the admin's own password/TOTP guessing. One elevation window
        # covers every target, so key on the actor only (default target="").
        decision = self._check_sensitive_limit(persistence, "admin_step_up")
        if not decision.allowed:
            self.step_up_error = rate_limited_message(
                "Too many verification attempts.",
                decision.retry_after_seconds,
            )
            self.force_refresh()
            return

        result = await perform_step_up(
            self.session,
            password=self.step_up_password,
            two_factor_code=self.step_up_2fa or None,
        )
        if not result.ok:
            self.step_up_error = result.error_message or "Verification failed."
            self.step_up_password = ""
            self.step_up_2fa = ""
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_step_up", "")

        identifier = self.step_up_pending_identifier
        new_role = self.step_up_pending_new_role
        self._hide_step_up_dialog()

        updated = await self._update_role(identifier, new_role)
        if updated:
            self.change_role_identifier = ""
            self.change_role_new_role = get_default_role()
            await self._load_user_data()

        # Surface the recovery-code warning only after _update_role runs, since it
        # resets change_role_error on the elevated path (admin.py:628). On a failed
        # update we leave its error message in place rather than clobber it.
        if result.used_recovery_code and updated:
            self.change_role_error = (
                "A recovery code was used. Generate a new set to stay protected."
            )

        self.force_refresh()

    async def _on_delete_user_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Handle the user deletion process from admin panel."""
        if not self._refresh_current_user_authorization():
            return

        if not self.current_user:
            self.delete_user_error = "You must be logged in to perform this action"
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        if not self.delete_user_identifier or self.delete_user_identifier == "":
            self.delete_user_error = "Please enter an email or username to delete"
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        if self.delete_user_confirmation != f"DELETE USER {self.delete_user_identifier}":
            self.delete_user_error = f'Please type "DELETE USER {self.delete_user_identifier}" exactly to confirm deletion'
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        persistence = self.session[Persistence]

        try:
            target_user = await persistence.get_user_by_email_or_username(self.delete_user_identifier)
        except KeyError:
            self.delete_user_error = f"User not found: {self.delete_user_identifier}"
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        target_role = target_user.role

        # Check if current user has permission to delete this user
        if not can_manage_role(self.current_user.role, target_role):
            self.delete_user_error = f"You do not have permission to delete users with role: {target_role} because your role is {self.current_user.role}"
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        decision = self._check_sensitive_limit(
            persistence,
            "admin_delete_user",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.delete_user_error = rate_limited_message(
                "Too many user deletion attempts.",
                decision.retry_after_seconds,
            )
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        result = await self._verify_actor_step_up(
            persistence,
            password=self.delete_user_step_up_password,
            two_factor_code=self.delete_user_step_up_2fa or None,
        )
        if not result.ok:
            self.delete_user_error = result.error_message or "Verification failed."
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()
            return

        # Store username for success message
        identifier_to_delete = self.delete_user_identifier

        # Delete the user
        try:
            success = await persistence.admin_delete_user(
                user_id=target_user.id,
                actor=self.current_user,
                client_ip=self._client_ip(),
            )
            if success:
                # Set success message
                self.delete_user_success = f"User '{identifier_to_delete}' has been successfully deleted"
                # Clear the fields
                self.delete_user_identifier = ""
                self.delete_user_confirmation = ""
                self._clear_delete_step_up_fields()
                self.delete_user_error = ""
                persistence.clear_rate_limit(
                    scope=sensitive_action_policy("admin_delete_user").scope,
                    key=rate_limit_key("admin_delete_user", f"{self.current_user.id}:{target_user.id}"),
                )
                # Refresh the page to show updated user list
                await self._load_user_data()
                self.force_refresh()
            else:
                self.delete_user_error = "Failed to delete user"
                self.delete_user_success = ""
                self._clear_delete_step_up_fields()
                self.force_refresh()
        except Exception as e:
            self.delete_user_error = self._admin_error_message("deleting user", e)
            self.delete_user_success = ""
            self._clear_delete_step_up_fields()
            self.force_refresh()

    async def _on_currency_submit(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Handle currency adjustments or absolute updates."""
        if not self._refresh_current_user_authorization():
            return

        if not self.current_user:
            self.currency_error = "You must be logged in to perform this action"
            self.currency_success = ""
            self.force_refresh()
            return

        identifier = (self.currency_user_identifier or "").strip()
        if not identifier:
            self.currency_error = "Please provide a user email, username, or ID"
            self.currency_success = ""
            self.force_refresh()
            return

        try:
            amount_decimal = Decimal((self.currency_amount or "").strip())
        except (InvalidOperation, AttributeError):
            self.currency_error = "Enter a valid numeric amount"
            self.currency_success = ""
            self.force_refresh()
            return

        persistence = self.session[Persistence]

        target_user: AppUser | None = None
        try:
            target_user = await persistence.get_user_by_id(uuid.UUID(identifier))
        except (ValueError, KeyError):
            try:
                target_user = await persistence.get_user_by_email_or_username(identifier)
            except KeyError:
                target_user = None

        if not target_user:
            self.currency_error = f"User not found: {identifier}"
            self.currency_success = ""
            self.force_refresh()
            return

        # Ensure the admin has permission to manage this user when roles differ.
        if (
            self.current_user.id != target_user.id
            and not can_manage_role(self.current_user.role, target_user.role)
        ):
            self.currency_error = (
                f"You do not have permission to update balances for users with role {target_user.role}."
            )
            self.currency_success = ""
            self.force_refresh()
            return

        reason = None
        if self.currency_reason:
            try:
                sanitized_reason = SecuritySanitizer.sanitize_string(self.currency_reason, 200)
            except Exception:
                sanitized_reason = None
            reason = sanitized_reason

        try:
            minor_amount = major_to_minor(amount_decimal)
        except ValueError:
            self.currency_error = "Amount must be a valid number"
            self.currency_success = ""
            self.force_refresh()
            return

        try:
            if self.currency_mode_is_set:
                entry = await persistence.set_currency_balance(
                    target_user.id,
                    new_balance_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    actor_user_id=self.current_user.id,
                    actor_role=self.current_user.role,
                    client_ip=self._client_ip(),
                )
                action_word = "Set"
            else:
                entry = await persistence.adjust_currency_balance(
                    target_user.id,
                    delta_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    actor_user_id=self.current_user.id,
                    actor_role=self.current_user.role,
                    client_ip=self._client_ip(),
                )
                action_word = "Adjusted"
        except ValueError as exc:
            self.currency_error = str(exc)
            self.currency_success = ""
            self.force_refresh()
            return

        delta_text = attach_currency_name(
            format_minor_amount(entry.delta), quantity_minor_units=entry.delta
        )
        balance_text = attach_currency_name(
            format_minor_amount(entry.balance_after), quantity_minor_units=entry.balance_after
        )

        self.currency_success = (
            f"{action_word} {target_user.email or target_user.username}'s balance. "
            f"Delta: {delta_text}. New balance: {balance_text}."
        )
        self.currency_error = ""
        self.currency_amount = ""
        await self._load_user_data()
        self.force_refresh()

    def _on_currency_mode_toggle(self, event: rio.SwitchChangeEvent) -> None:
        """Toggle between adjust and set modes."""
        self.currency_mode_is_set = event.is_on
        self.force_refresh()

    def _on_create_verified_toggle(self, event: rio.SwitchChangeEvent) -> None:
        self.create_user_is_verified = event.is_on
        self.force_refresh()

    def _on_active_status_toggle(self, event: rio.SwitchChangeEvent) -> None:
        self.active_user_is_active = event.is_on
        self.force_refresh()

    def _responsive_form_layout(
        self,
        *children: rio.Component,
        proportions: list[int],
    ) -> rio.Component:
        """Render equal-width rows on desktop and wrapping layouts on mobile."""
        if self.is_mobile:
            return rio.FlowContainer(
                *children,
                row_spacing=self.flow_spacing,
                column_spacing=self.flow_spacing,
            )

        return rio.Row(
            *children,
            spacing=self.flow_spacing,
            proportions=proportions,
        )

    def _build_step_up_dialog(self) -> rio.Component:
        """Inline re-auth prompt shown before a sensitive role change.

        Built inline on the (responsive-safe) AdminPage so no new component needs
        to inherit ResponsiveComponent. The 2FA field is only shown when the
        current admin has 2FA enabled.
        """
        contents: list[rio.Component] = [
            rio.Text("Confirm it's you", style="heading3"),
            rio.Text(
                f"Re-enter your credentials to change "
                f"{self.step_up_pending_identifier}'s role to "
                f"{self.step_up_pending_new_role}.",
                overflow="wrap",
            ),
        ]

        if self.current_user and self.current_user.auth_provider == "password":
            contents.append(rio.TextInput(
                label="Your Password",
                text=self.bind().step_up_password,
                is_secret=True,
                on_confirm=self._on_step_up_submit,
            ))

        if self.current_user and self.current_user.two_factor_enabled:
            contents.append(
                rio.TextInput(
                    label="2FA or Recovery Code",
                    text=self.bind().step_up_2fa,
                    is_secret=True,
                    on_confirm=self._on_step_up_submit,
                )
            )

        contents.append(
            rio.Row(
                rio.Button(
                    "Confirm",
                    on_press=self._on_step_up_submit,
                    shape="rounded",
                ),
                rio.Button(
                    "Cancel",
                    on_press=self._on_step_up_cancel,
                    shape="rounded",
                    style="minor",
                ),
                spacing=1,
            )
        )

        if self.step_up_error:
            contents.append(
                rio.Banner(text=self.step_up_error, style="danger", margin_top=1)
            )

        return rio.Card(
            rio.Column(*contents, spacing=1, margin=2),
            margin_top=1,
        )

    def build(self) -> rio.Component:
        if not self.current_user or self.df is None:
            return rio.Text("Error: Could not load user information")

        requires_step_up_password = self.current_user.auth_provider == "password"
        requires_step_up_2fa = self.current_user.two_factor_enabled

        delete_user_inputs: list[rio.Component] = [
            rio.TextInput(
                label="Email or Username to Delete",
                text=self.bind().delete_user_identifier,
                on_confirm=self._on_delete_user_pressed,
            ),
            rio.TextInput(
                label='Type "DELETE USER identifier" to confirm',
                text=self.bind().delete_user_confirmation,
                on_confirm=self._on_delete_user_pressed,
            ),
        ]
        if requires_step_up_password:
            delete_user_inputs.append(rio.TextInput(
                label="Your Password",
                text=self.bind().delete_user_step_up_password,
                is_secret=True,
                on_confirm=self._on_delete_user_pressed,
            ))
        if requires_step_up_2fa:
            delete_user_inputs.append(
                rio.TextInput(
                    label="2FA or Recovery Code",
                    text=self.bind().delete_user_step_up_2fa,
                    is_secret=True,
                    on_confirm=self._on_delete_user_pressed,
                )
            )
        delete_user_inputs.append(
            rio.Button(
                "Delete User",
                on_press=self._on_delete_user_pressed,
                shape="rounded",
            )
        )
        return CenterComponent(
            rio.Column(
                rio.Text(
                    "User Management",
                    style="heading1",
                    margin_bottom=2,
                    overflow="wrap",
                ),

            # Users table - wrap in ScrollContainer for mobile horizontal scroll
            rio.Card(
                rio.Column(
                    rio.Text(
                        "All Users",
                        style="heading2",
                        margin_bottom=1,
                    ),

                    rio.ScrollContainer(
                        rio.Table(
                            data=self.df,
                            show_row_numbers=False,
                            min_height=17,
                        ),
                        scroll_x="auto",
                        scroll_y="auto",
                        min_height=17,
                    ),

                    margin=2,
                ),
            ),

            rio.Text(
                "Create User",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="Email",
                    text=self.bind().create_user_email,
                ),
                rio.TextInput(
                    label="Username (optional)",
                    text=self.bind().create_user_username,
                ),
                rio.TextInput(
                    label="Full Name (optional)",
                    text=self.bind().create_user_full_name,
                ),
                proportions=[1, 1, 1],
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="Temporary Password",
                    text=self.bind().create_user_password,
                    is_secret=True,
                    on_confirm=self._on_create_user_pressed,
                ),
                rio.Dropdown(
                    label="Role",
                    options={
                        role: role
                        for role in get_manageable_roles(self.current_user.role)
                    },
                    selected_value=self.bind().create_user_role,
                ),
                rio.Row(
                    rio.Text("Verified"),
                    rio.Switch(
                        is_on=self.create_user_is_verified,
                        on_change=self._on_create_verified_toggle,
                    ),
                    spacing=1,
                ),
                rio.Button(
                    "Create User",
                    on_press=self._on_create_user_pressed,
                    shape="rounded",
                ),
                proportions=[1, 1, 1, 1],
            ),

            rio.Banner(
                text=self.create_user_success,
                style="success",
                margin_top=1,
            ) if self.create_user_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.create_user_error,
                style="danger",
                margin_top=1,
            ) if self.create_user_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Text(
                "Edit User",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="User Email / Username / ID",
                    text=self.bind().edit_user_identifier,
                ),
                rio.TextInput(
                    label="New Email (optional)",
                    text=self.bind().edit_user_email,
                ),
                rio.TextInput(
                    label="New Username (optional)",
                    text=self.bind().edit_user_username,
                ),
                rio.TextInput(
                    label="New Full Name (optional)",
                    text=self.bind().edit_user_full_name,
                    on_confirm=self._on_edit_user_pressed,
                ),
                proportions=[1, 1, 1, 1],
            ),

            rio.Button(
                "Update User",
                on_press=self._on_edit_user_pressed,
                shape="rounded",
                margin_top=1,
            ),

            rio.Banner(
                text=self.edit_user_success,
                style="success",
                margin_top=1,
            ) if self.edit_user_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.edit_user_error,
                style="danger",
                margin_top=1,
            ) if self.edit_user_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Text(
                "Account Status",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="User Email / Username / ID",
                    text=self.bind().active_user_identifier,
                    on_confirm=self._on_set_active_pressed,
                ),
                rio.Row(
                    rio.Text("Active"),
                    rio.Switch(
                        is_on=self.active_user_is_active,
                        on_change=self._on_active_status_toggle,
                    ),
                    spacing=1,
                ),
                rio.Button(
                    "Apply Status",
                    on_press=self._on_set_active_pressed,
                    shape="rounded",
                ),
                proportions=[1, 1, 1],
            ),

            rio.TextInput(
                label=(
                    f'Type "DEACTIVATE {self.active_user_identifier.strip()}" to confirm deactivation'
                    if self.active_user_identifier.strip()
                    else 'Enter the user\'s email above, then type "DEACTIVATE <email>" here to confirm'
                ),
                text=self.bind().active_user_confirmation,
                on_confirm=self._on_set_active_pressed,
            ) if not self.active_user_is_active else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.active_user_success,
                style="success",
                margin_top=1,
            ) if self.active_user_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.active_user_error,
                style="danger",
                margin_top=1,
            ) if self.active_user_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Text(
                "Password Reset",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="User Email / Username / ID",
                    text=self.bind().reset_user_identifier,
                    on_confirm=self._on_send_reset_pressed,
                ),
                rio.Button(
                    "Send Reset Email",
                    on_press=self._on_send_reset_pressed,
                    shape="rounded",
                ),
                proportions=[2, 1],
            ),

            rio.Banner(
                text=self.reset_user_success,
                style="success",
                margin_top=1,
            ) if self.reset_user_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.reset_user_error,
                style="danger",
                margin_top=1,
            ) if self.reset_user_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Text(
                "Change Role",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="Email or Username to Change Role",
                    text=self.bind().change_role_identifier,
                ),
                rio.Dropdown(
                    label="New Role",
                    options={
                        role: role
                        for role in get_manageable_roles(self.current_user.role)
                    },
                    selected_value=self.bind().change_role_new_role,
                ),
                rio.Button(
                    "Change Role",
                    on_press=self._on_change_role_pressed,
                    shape="rounded",
                ),
                proportions=[1, 1, 1],
            ),

            rio.Text(
                f"about to change {self.change_role_identifier}'s role to {self.change_role_new_role}",
                margin_top=1,
            ) if self.change_role_identifier else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.change_role_error,
                style="danger",
                margin_top=1,
            ),

            self._build_step_up_dialog() if self.step_up_visible else rio.Spacer(
                min_height=0, grow_x=False, grow_y=False
            ),


            rio.Text(
                "Currency Management",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                rio.TextInput(
                    label="User Email / Username / ID",
                    text=self.bind().currency_user_identifier,
                ),
                rio.TextInput(
                    label="Amount",
                    text=self.bind().currency_amount,
                    on_confirm=self._on_currency_submit,
                ),
                rio.TextInput(
                    label="Reason (optional)",
                    text=self.bind().currency_reason,
                    on_confirm=self._on_currency_submit,
                ),
                proportions=[1, 1, 1],
            ),

            self._responsive_form_layout(
                rio.Text("Set absolute balance"),
                rio.Switch(
                    is_on=self.currency_mode_is_set,
                    on_change=self._on_currency_mode_toggle,
                ),
                rio.Button(
                    "Apply",
                    on_press=self._on_currency_submit,
                    shape="rounded",
                ),
                proportions=[1, 1, 1],
            ),

            rio.Banner(
                text=self.currency_success,
                style="success",
                margin_top=1,
            ) if self.currency_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.currency_error,
                style="danger",
                margin_top=1,
            ) if self.currency_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),


            rio.Text(
                "Delete User",
                style="heading3",
                margin_top=2,
                margin_bottom=1,
            ),

            self._responsive_form_layout(
                *delete_user_inputs,
                proportions=[1] * len(delete_user_inputs),
            ),

            rio.Banner(
                text=self.delete_user_success,
                style="success",
                margin_top=1,
            ) if self.delete_user_success else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

            rio.Banner(
                text=self.delete_user_error,
                style="danger",
                margin_top=1,
            ) if self.delete_user_error else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

                align_x=0.5,
                margin=self.page_margin,
            ),
            width_percent=WIDTH_FULL,
        )
