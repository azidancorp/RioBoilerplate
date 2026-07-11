from __future__ import annotations

from dataclasses import field
from decimal import Decimal, InvalidOperation
import logging
import sqlite3
import uuid
import typing as t
import pandas as pd

import rio
from app.config import config
from app.password_policy import evaluate_new_password
from app.persistence import AdminMutationContext, Persistence
from app.data_models import AppUser, UserSession
from app.permissions import (
    can_manage_role,
    check_access,
    get_default_role,
    get_manageable_roles,
    get_role_level,
)
from app.request_context import context_from_rio_session
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import (
    StepUpResult,
    refresh_attached_user_session,
    reject_stale_user_session,
    verify_step_up_credentials,
)
from app.currency import major_to_minor, format_minor_amount, attach_currency_name
from app.validation import SecuritySanitizer
from app.scripts.message_utils import send_password_reset_email
from app.scripts.utils import (
    get_password_strength,
    get_password_strength_color,
    get_password_strength_status,
)
from app.components.center_component import CenterComponent
from app.components.responsive import ResponsiveComponent, WIDTH_FULL

logger = logging.getLogger(__name__)
RECOVERY_CODE_USED_MESSAGE = (
    "A recovery code was used. Generate a new set to stay protected."
)


def _with_recovery_code_warning(message: str, used_recovery_code: bool) -> str:
    if not used_recovery_code:
        return message
    if not message:
        return RECOVERY_CODE_USED_MESSAGE
    return f"{message} {RECOVERY_CODE_USED_MESSAGE}"


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
    create_user_password_strength: int = 0
    create_user_acknowledge_weak_password: bool = False
    create_user_role: str = field(default_factory=get_default_role)
    create_user_is_verified: bool = False
    create_user_step_up_password: str = ""
    create_user_step_up_2fa: str = ""
    create_user_error: str = ""
    create_user_success: str = ""

    # User profile edit fields
    edit_user_identifier: str = ""
    edit_user_email: str = ""
    edit_user_username: str = ""
    edit_user_full_name: str = ""
    edit_user_step_up_password: str = ""
    edit_user_step_up_2fa: str = ""
    edit_user_error: str = ""
    edit_user_success: str = ""

    # User active-state fields
    active_user_identifier: str = ""
    active_user_is_active: bool = True
    active_user_confirmation: str = ""
    active_user_step_up_password: str = ""
    active_user_step_up_2fa: str = ""
    active_user_error: str = ""
    active_user_success: str = ""

    # Password reset fields
    reset_user_identifier: str = ""
    reset_user_step_up_password: str = ""
    reset_user_step_up_2fa: str = ""
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
    currency_step_up_password: str = ""
    currency_step_up_2fa: str = ""
    currency_error: str = ""
    currency_success: str = ""

    # Step-up re-auth dialog state. A role change always prompts for the
    # acting admin's own credentials; the pending action is stashed so it can
    # be replayed once verification succeeds. Verification is scoped to that
    # single action.
    step_up_visible: bool = False
    step_up_password: str = ""
    step_up_2fa: str = ""
    step_up_error: str = ""
    step_up_pending_identifier: str = ""
    step_up_pending_user_id: str = ""
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
            key=rate_limit_key(scope, f"{actor}:{target}" if target else actor),
        )

    def _client_ip(self) -> str | None:
        """Best-effort source IP for audit attribution."""
        return context_from_rio_session(self.session).client_ip

    def _admin_mutation_context(self) -> AdminMutationContext:
        """Build the live-session context required by admin persistence writes."""
        try:
            user_session = self.session[UserSession]
        except KeyError as exc:
            raise PermissionError(
                "Your session has expired. Please log in again."
            ) from exc
        return AdminMutationContext(
            auth_token=user_session.id,
            client_ip=self._client_ip(),
        )

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
            key=rate_limit_key(
                scope,
                f"{self.current_user.id}:{target}" if target else self.current_user.id,
            ),
        )

    def _clear_delete_step_up_fields(self) -> None:
        self.delete_user_step_up_password = ""
        self.delete_user_step_up_2fa = ""

    def _clear_create_step_up_fields(self) -> None:
        self.create_user_step_up_password = ""
        self.create_user_step_up_2fa = ""

    def _clear_active_step_up_fields(self) -> None:
        self.active_user_step_up_password = ""
        self.active_user_step_up_2fa = ""

    def _clear_reset_step_up_fields(self) -> None:
        self.reset_user_step_up_password = ""
        self.reset_user_step_up_2fa = ""

    def _clear_currency_step_up_fields(self) -> None:
        self.currency_step_up_password = ""
        self.currency_step_up_2fa = ""

    def _clear_edit_step_up_fields(self) -> None:
        self.edit_user_step_up_password = ""
        self.edit_user_step_up_2fa = ""

    def _create_user_step_up_required(self, role: str | None = None) -> bool:
        candidate_role = self.create_user_role if role is None else role
        try:
            return get_role_level((candidate_role or "").strip()) < get_role_level(
                get_default_role()
            )
        except ValueError:
            return False

    def _edit_email_step_up_may_be_required(self) -> bool:
        new_email = (self.edit_user_email or "").strip()
        if not new_email:
            return False

        identifier = (self.edit_user_identifier or "").strip().lower()
        if not identifier:
            return True

        for user in self.users:
            if identifier not in {
                str(user.id).lower(),
                user.email.lower(),
                (user.username or "").lower(),
            }:
                continue
            return new_email.lower() != user.email.lower()

        return True

    def _step_up_unavailable_message(self) -> str | None:
        if (
            self.current_user
            and self.current_user.auth_provider != "password"
            and not self.current_user.two_factor_enabled
        ):
            return "Set up a password or 2FA to perform this action."
        return None

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

        unavailable_message = self._step_up_unavailable_message()
        if unavailable_message:
            return StepUpResult(ok=False, error_message=unavailable_message)

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
        if isinstance(exc, KeyError):
            return "The user no longer exists. Refresh the page and try again."
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
            self._clear_create_step_up_fields()
            return

        if not self.current_user:
            self.create_user_error = "You must be logged in to perform this action"
            self.create_user_success = ""
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

        email = (self.create_user_email or "").strip()
        password = self.create_user_password or ""
        role = (self.create_user_role or "").strip()
        username = (self.create_user_username or "").strip() or None
        full_name = (self.create_user_full_name or "").strip() or None
        is_verified = bool(self.create_user_is_verified)
        step_up_required = self._create_user_step_up_required(role)

        if not email:
            self.create_user_error = "Please enter an email"
            self.create_user_success = ""
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

        password_policy = evaluate_new_password(
            password,
            acknowledged_weak=self.create_user_acknowledge_weak_password,
        )
        if not password_policy.ok:
            self.create_user_error = (
                password_policy.message or "Password is not allowed."
            )
            self.create_user_success = ""
            self._clear_create_step_up_fields()
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
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        unavailable_message = (
            self._step_up_unavailable_message() if step_up_required else None
        )
        if unavailable_message:
            self.create_user_error = unavailable_message
            self.create_user_success = ""
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

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
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

        used_recovery_code = False
        if step_up_required:
            try:
                result = await self._verify_actor_step_up(
                    persistence,
                    password=self.create_user_step_up_password,
                    two_factor_code=self.create_user_step_up_2fa or None,
                )
            finally:
                self._clear_create_step_up_fields()
            if not result.ok:
                self.create_user_error = result.error_message or "Verification failed."
                self.create_user_success = ""
                self.force_refresh()
                return
            used_recovery_code = result.used_recovery_code

            if not self._refresh_current_user_authorization():
                return
            try:
                can_create_role = bool(
                    self.current_user
                    and can_manage_role(self.current_user.role, role)
                )
            except ValueError:
                can_create_role = False
            if not can_create_role:
                self.create_user_error = _with_recovery_code_warning(
                    f"You do not have permission to create users with role: {role}",
                    used_recovery_code,
                )
                self.create_user_success = ""
                self.force_refresh()
                return
        else:
            self._clear_create_step_up_fields()

        try:
            created = await persistence.admin_create_user(
                email=email,
                password=password,
                role=role,
                admin_context=self._admin_mutation_context(),
                username=username,
                full_name=full_name,
                is_verified=is_verified,
                acknowledged_weak=self.create_user_acknowledge_weak_password,
            )
        except Exception as exc:
            self.create_user_error = _with_recovery_code_warning(
                self._admin_error_message("creating user", exc),
                used_recovery_code,
            )
            self.create_user_success = ""
            self._clear_create_step_up_fields()
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_create_user", email)
        self.create_user_success = f"Created user {created.email}"
        self.create_user_error = _with_recovery_code_warning(
            "",
            used_recovery_code,
        )
        self.create_user_email = ""
        self.create_user_username = ""
        self.create_user_full_name = ""
        self.create_user_password = ""
        self.create_user_password_strength = 0
        self.create_user_acknowledge_weak_password = False
        self.create_user_role = get_default_role()
        self.create_user_is_verified = False
        self._clear_create_step_up_fields()
        await self._load_user_data()
        self.force_refresh()

    async def _on_edit_user_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            return

        identifier = (self.edit_user_identifier or "").strip()
        if not identifier:
            self.edit_user_error = "Please enter a user email, username, or ID"
            self.edit_user_success = ""
            self._clear_edit_step_up_fields()
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
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.edit_user_error = f"User not found: {identifier}"
            self.edit_user_success = ""
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.edit_user_error = (
                f"You do not have permission to edit users with role: {target_user.role}"
            )
            self.edit_user_success = ""
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        email_is_changing = (
            updates["email"] is not None
            and updates["email"].lower() != target_user.email.lower()
        )
        expected_email = target_user.email
        unavailable_message = (
            self._step_up_unavailable_message()
            if email_is_changing
            else None
        )
        if unavailable_message:
            self.edit_user_error = unavailable_message
            self.edit_user_success = ""
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

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
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

        used_recovery_code = False
        if email_is_changing:
            try:
                result = await self._verify_actor_step_up(
                    persistence,
                    password=self.edit_user_step_up_password,
                    two_factor_code=self.edit_user_step_up_2fa or None,
                )
            finally:
                self._clear_edit_step_up_fields()
            if not result.ok:
                self.edit_user_error = result.error_message or "Verification failed."
                self.edit_user_success = ""
                self.force_refresh()
                return
            used_recovery_code = result.used_recovery_code

            if not self._refresh_current_user_authorization():
                return
            try:
                target_user = await persistence.get_user_by_id(target_user.id)
            except KeyError:
                self.edit_user_error = _with_recovery_code_warning(
                    f"User not found: {identifier}",
                    used_recovery_code,
                )
                self.edit_user_success = ""
                self.force_refresh()
                return
            if not self._can_manage_user(target_user):
                self.edit_user_error = _with_recovery_code_warning(
                    f"You do not have permission to edit users with role: {target_user.role}",
                    used_recovery_code,
                )
                self.edit_user_success = ""
                self.force_refresh()
                return
        else:
            self._clear_edit_step_up_fields()

        try:
            updated = await persistence.admin_update_user_profile(
                target_user.id,
                admin_context=self._admin_mutation_context(),
                email=updates["email"],
                username=updates["username"],
                full_name=updates["full_name"],
                expected_email=expected_email,
            )
        except Exception as exc:
            self.edit_user_error = _with_recovery_code_warning(
                self._admin_error_message("updating user", exc),
                used_recovery_code,
            )
            self.edit_user_success = ""
            self._clear_edit_step_up_fields()
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_edit_user", str(target_user.id))
        self.edit_user_success = f"Updated user {updated.email}"
        self.edit_user_error = _with_recovery_code_warning(
            "",
            used_recovery_code,
        )
        self.edit_user_identifier = ""
        self.edit_user_email = ""
        self.edit_user_username = ""
        self.edit_user_full_name = ""
        self._clear_edit_step_up_fields()
        await self._load_user_data()
        self.force_refresh()

    async def _on_set_active_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            self._clear_active_step_up_fields()
            return

        identifier = (self.active_user_identifier or "").strip()
        is_active = bool(self.active_user_is_active)
        confirmation = (self.active_user_confirmation or "").strip()
        if not identifier:
            self.active_user_error = "Please enter a user email, username, or ID"
            self.active_user_success = ""
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.active_user_error = f"User not found: {identifier}"
            self.active_user_success = ""
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.active_user_error = (
                f"You do not have permission to update users with role: {target_user.role}"
            )
            self.active_user_success = ""
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

        if not is_active:
            expected_confirmation = f"DEACTIVATE {target_user.email}"
            if confirmation != expected_confirmation:
                self.active_user_error = (
                    f'Type "{expected_confirmation}" to confirm deactivation.'
                )
                self.active_user_success = ""
                self._clear_active_step_up_fields()
                self.force_refresh()
                return

        persistence = self.session[Persistence]
        unavailable_message = self._step_up_unavailable_message()
        if unavailable_message:
            self.active_user_error = unavailable_message
            self.active_user_success = ""
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

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
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

        try:
            result = await self._verify_actor_step_up(
                persistence,
                password=self.active_user_step_up_password,
                two_factor_code=self.active_user_step_up_2fa or None,
            )
        finally:
            self._clear_active_step_up_fields()
        if not result.ok:
            self.active_user_error = result.error_message or "Verification failed."
            self.active_user_success = ""
            self.force_refresh()
            return

        if not self._refresh_current_user_authorization():
            return
        try:
            target_user = await persistence.get_user_by_id(target_user.id)
        except KeyError:
            self.active_user_error = _with_recovery_code_warning(
                f"User not found: {identifier}",
                result.used_recovery_code,
            )
            self.active_user_success = ""
            self.force_refresh()
            return
        if not self._can_manage_user(target_user):
            self.active_user_error = _with_recovery_code_warning(
                f"You do not have permission to update users with role: {target_user.role}",
                result.used_recovery_code,
            )
            self.active_user_success = ""
            self.force_refresh()
            return

        try:
            updated = await persistence.admin_set_user_active(
                target_user.id,
                is_active,
                admin_context=self._admin_mutation_context(),
            )
        except Exception as exc:
            self.active_user_error = _with_recovery_code_warning(
                self._admin_error_message(
                    "updating account status",
                    exc,
                ),
                result.used_recovery_code,
            )
            self.active_user_success = ""
            self._clear_active_step_up_fields()
            self.force_refresh()
            return

        self._clear_rate_limit(persistence, "admin_set_user_active", str(target_user.id))
        status_text = "activated" if updated.is_active else "deactivated"
        self.active_user_success = f"User {updated.email} has been {status_text}"
        self.active_user_error = _with_recovery_code_warning(
            "",
            result.used_recovery_code,
        )
        self.active_user_identifier = ""
        self.active_user_confirmation = ""
        self.active_user_is_active = True
        self._clear_active_step_up_fields()
        await self._load_user_data()
        self.force_refresh()

    async def _on_send_reset_pressed(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        if not self._refresh_current_user_authorization():
            self._clear_reset_step_up_fields()
            return

        identifier = (self.reset_user_identifier or "").strip()
        if not identifier:
            self.reset_user_error = "Please enter a user email, username, or ID"
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        try:
            target_user = await self._get_target_user(identifier)
        except KeyError:
            self.reset_user_error = f"User not found: {identifier}"
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        if not self._can_manage_user(target_user):
            self.reset_user_error = (
                f"You do not have permission to reset users with role: {target_user.role}"
            )
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        if not target_user.is_active:
            self.reset_user_error = "Reactivate this user before sending a password reset"
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        persistence = self.session[Persistence]
        unavailable_message = self._step_up_unavailable_message()
        if unavailable_message:
            self.reset_user_error = unavailable_message
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

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
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        try:
            result = await self._verify_actor_step_up(
                persistence,
                password=self.reset_user_step_up_password,
                two_factor_code=self.reset_user_step_up_2fa or None,
            )
        finally:
            self._clear_reset_step_up_fields()
        if not result.ok:
            self.reset_user_error = result.error_message or "Verification failed."
            self.reset_user_success = ""
            self.force_refresh()
            return

        if not self._refresh_current_user_authorization():
            return
        try:
            target_user = await persistence.get_user_by_id(target_user.id)
        except KeyError:
            self.reset_user_error = _with_recovery_code_warning(
                f"User not found: {identifier}",
                result.used_recovery_code,
            )
            self.reset_user_success = ""
            self.force_refresh()
            return
        if not self._can_manage_user(target_user):
            self.reset_user_error = _with_recovery_code_warning(
                f"You do not have permission to reset users with role: {target_user.role}",
                result.used_recovery_code,
            )
            self.reset_user_success = ""
            self.force_refresh()
            return
        if not target_user.is_active:
            self.reset_user_error = _with_recovery_code_warning(
                "Reactivate this user before sending a password reset",
                result.used_recovery_code,
            )
            self.reset_user_success = ""
            self.force_refresh()
            return

        try:
            issuance = await persistence.admin_issue_password_reset(
                target_user.id,
                admin_context=self._admin_mutation_context(),
            )
            send_password_reset_email(
                recipient=issuance.recipient_email,
                token=issuance.token,
                valid_until=issuance.valid_until,
            )
        except Exception as exc:
            self.reset_user_error = _with_recovery_code_warning(
                self._admin_error_message(
                    "sending password reset",
                    exc,
                ),
                result.used_recovery_code,
            )
            self.reset_user_success = ""
            self._clear_reset_step_up_fields()
            self.force_refresh()
            return

        self._clear_rate_limit(
            persistence,
            "admin_send_password_reset",
            str(target_user.id),
        )
        self.reset_user_success = (
            f"Password reset email sent to {issuance.recipient_email}"
        )
        self.reset_user_error = _with_recovery_code_warning(
            "",
            result.used_recovery_code,
        )
        self.reset_user_identifier = ""
        self._clear_reset_step_up_fields()
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

    async def _update_role(
        self,
        identifier: str,
        new_role: str,
        *,
        step_up_verified: bool = False,
        action_limit_checked_for: uuid.UUID | None = None,
        target_user_id: uuid.UUID | None = None,
    ) -> bool:
        """Update a user's role."""
        if not self._refresh_current_user_authorization():
            return False

        if not self.current_user:
            self.change_role_error = "You must be logged in to perform this action"
            return False

        persistence = self.session[Persistence]
        try:
            if target_user_id is None:
                target_user = await persistence.get_user_by_email_or_username(identifier)
            else:
                target_user = await persistence.get_user_by_id(target_user_id)
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

        # Per-action step-up: every role change requires the acting admin's own
        # credentials. The action is legitimate at this point (permissions
        # already checked), so prompting is warranted. `step_up_verified` is
        # only passed by `_on_step_up_submit` immediately after a successful
        # credential check.
        if not step_up_verified:
            unavailable_message = self._step_up_unavailable_message()
            if unavailable_message:
                self.change_role_error = unavailable_message
                return False
            self._show_step_up_dialog(
                identifier=identifier,
                user_id=target_user.id,
                new_role=new_role,
            )
            return False

        if action_limit_checked_for != target_user.id:
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
            await persistence.admin_update_user_role(
                target_user.id,
                new_role,
                admin_context=self._admin_mutation_context(),
            )
            persistence.clear_rate_limit(
                scope=sensitive_action_policy("admin_change_role").scope,
                key=rate_limit_key("admin_change_role", f"{self.current_user.id}:{target_user.id}"),
            )
            return True
        except Exception as exc:
            self.change_role_error = self._admin_error_message("updating role", exc)
            return False

    def _show_step_up_dialog(
        self,
        *,
        identifier: str,
        user_id: uuid.UUID,
        new_role: str,
    ) -> None:
        """Stash the pending role change and reveal the step-up re-auth dialog."""
        self.step_up_pending_identifier = identifier
        self.step_up_pending_user_id = str(user_id)
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
        self.step_up_pending_user_id = ""
        self.step_up_pending_new_role = ""

    def _on_step_up_cancel(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        self._hide_step_up_dialog()
        self.force_refresh()

    async def _on_step_up_submit(self, _: rio.TextInputConfirmEvent | None = None) -> None:
        """Verify the admin's own credentials, then replay the role change."""
        if not self._refresh_current_user_authorization():
            return

        persistence = self.session[Persistence]
        identifier = self.step_up_pending_identifier
        user_id = self.step_up_pending_user_id
        new_role = self.step_up_pending_new_role

        try:
            target_user = await persistence.get_user_by_id(uuid.UUID(user_id))
        except (ValueError, KeyError):
            self.step_up_error = f"User {identifier} not found"
            self.step_up_password = ""
            self.step_up_2fa = ""
            self.force_refresh()
            return

        decision = self._check_sensitive_limit(
            persistence,
            "admin_change_role",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.step_up_error = rate_limited_message(
                "Too many role-change attempts.",
                decision.retry_after_seconds,
            )
            self.step_up_password = ""
            self.step_up_2fa = ""
            self.force_refresh()
            return

        try:
            result = await self._verify_actor_step_up(
                persistence,
                password=self.step_up_password,
                two_factor_code=self.step_up_2fa or None,
            )
        except Exception:
            logger.exception("Admin step-up verification failed")
            self.step_up_error = (
                "Could not verify your credentials. Please try again."
            )
            self.force_refresh()
            return
        finally:
            self.step_up_password = ""
            self.step_up_2fa = ""
        if not result.ok:
            self.step_up_error = result.error_message or "Verification failed."
            self.force_refresh()
            return

        self._hide_step_up_dialog()

        updated = await self._update_role(
            identifier,
            new_role,
            step_up_verified=True,
            action_limit_checked_for=target_user.id,
            target_user_id=target_user.id,
        )
        if updated:
            self.change_role_identifier = ""
            self.change_role_new_role = get_default_role()
            await self._load_user_data()

        # Surface the recovery-code warning only after _update_role runs, since
        # it resets change_role_error on the success path. Preserve any mutation
        # error because the one-time code was still consumed during step-up.
        if result.used_recovery_code:
            self.change_role_error = _with_recovery_code_warning(
                self.change_role_error,
                True,
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

        unavailable_message = self._step_up_unavailable_message()
        if unavailable_message:
            self.delete_user_error = unavailable_message
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

        identifier_to_delete = self.delete_user_identifier
        try:
            result = await self._verify_actor_step_up(
                persistence,
                password=self.delete_user_step_up_password,
                two_factor_code=self.delete_user_step_up_2fa or None,
            )
        finally:
            self._clear_delete_step_up_fields()
        if not result.ok:
            self.delete_user_error = result.error_message or "Verification failed."
            self.delete_user_success = ""
            self.force_refresh()
            return

        if not self._refresh_current_user_authorization():
            return
        try:
            target_user = await persistence.get_user_by_id(target_user.id)
        except KeyError:
            self.delete_user_error = _with_recovery_code_warning(
                f"User not found: {identifier_to_delete}",
                result.used_recovery_code,
            )
            self.delete_user_success = ""
            self.force_refresh()
            return
        if not self._can_manage_user(target_user):
            self.delete_user_error = _with_recovery_code_warning(
                f"You do not have permission to delete users with role: {target_user.role}",
                result.used_recovery_code,
            )
            self.delete_user_success = ""
            self.force_refresh()
            return

        # Delete the user
        try:
            success = await persistence.admin_delete_user(
                user_id=target_user.id,
                admin_context=self._admin_mutation_context(),
            )
            if success:
                # Set success message
                self.delete_user_success = f"User '{identifier_to_delete}' has been successfully deleted"
                # Clear the fields
                self.delete_user_identifier = ""
                self.delete_user_confirmation = ""
                self._clear_delete_step_up_fields()
                self.delete_user_error = _with_recovery_code_warning(
                    "",
                    result.used_recovery_code,
                )
                persistence.clear_rate_limit(
                    scope=sensitive_action_policy("admin_delete_user").scope,
                    key=rate_limit_key("admin_delete_user", f"{self.current_user.id}:{target_user.id}"),
                )
                # Refresh the page to show updated user list
                await self._load_user_data()
                self.force_refresh()
            else:
                self.delete_user_error = _with_recovery_code_warning(
                    "Failed to delete user",
                    result.used_recovery_code,
                )
                self.delete_user_success = ""
                self._clear_delete_step_up_fields()
                self.force_refresh()
        except Exception as e:
            self.delete_user_error = _with_recovery_code_warning(
                self._admin_error_message("deleting user", e),
                result.used_recovery_code,
            )
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
            self._clear_currency_step_up_fields()
            self.force_refresh()
            return

        identifier = (self.currency_user_identifier or "").strip()
        if not identifier:
            self.currency_error = "Please provide a user email, username, or ID"
            self.currency_success = ""
            self._clear_currency_step_up_fields()
            self.force_refresh()
            return

        try:
            amount_decimal = Decimal((self.currency_amount or "").strip())
        except (InvalidOperation, AttributeError):
            self.currency_error = "Enter a valid numeric amount"
            self.currency_success = ""
            self._clear_currency_step_up_fields()
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
            self._clear_currency_step_up_fields()
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
            self._clear_currency_step_up_fields()
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
            self._clear_currency_step_up_fields()
            self.force_refresh()
            return

        unavailable_message = self._step_up_unavailable_message()
        if unavailable_message:
            self.currency_error = unavailable_message
            self.currency_success = ""
            self._clear_currency_step_up_fields()
            self.force_refresh()
            return

        decision = self._check_sensitive_limit(
            persistence,
            "admin_currency_update",
            target=str(target_user.id),
        )
        if not decision.allowed:
            self.currency_error = rate_limited_message(
                "Too many currency update attempts.",
                decision.retry_after_seconds,
            )
            self.currency_success = ""
            self._clear_currency_step_up_fields()
            self.force_refresh()
            return

        try:
            result = await self._verify_actor_step_up(
                persistence,
                password=self.currency_step_up_password,
                two_factor_code=self.currency_step_up_2fa or None,
            )
        finally:
            self._clear_currency_step_up_fields()
        if not result.ok:
            self.currency_error = result.error_message or "Verification failed."
            self.currency_success = ""
            self.force_refresh()
            return

        if not self._refresh_current_user_authorization():
            return
        try:
            target_user = await persistence.get_user_by_id(target_user.id)
        except KeyError:
            self.currency_error = _with_recovery_code_warning(
                f"User not found: {identifier}",
                result.used_recovery_code,
            )
            self.currency_success = ""
            self.force_refresh()
            return
        if (
            self.current_user.id != target_user.id
            and not self._can_manage_user(target_user)
        ):
            self.currency_error = _with_recovery_code_warning(
                f"You do not have permission to update balances for users with role {target_user.role}.",
                result.used_recovery_code,
            )
            self.currency_success = ""
            self.force_refresh()
            return

        try:
            if self.currency_mode_is_set:
                entry = await persistence.admin_set_currency_balance(
                    target_user.id,
                    new_balance_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    admin_context=self._admin_mutation_context(),
                )
                action_word = "Set"
            else:
                entry = await persistence.admin_adjust_currency_balance(
                    target_user.id,
                    delta_minor=minor_amount,
                    reason=reason,
                    metadata=None,
                    admin_context=self._admin_mutation_context(),
                )
                action_word = "Adjusted"
        except Exception as exc:
            self.currency_error = _with_recovery_code_warning(
                self._admin_error_message("updating currency balance", exc),
                result.used_recovery_code,
            )
            self.currency_success = ""
            self._clear_currency_step_up_fields()
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
        self.currency_error = _with_recovery_code_warning(
            "",
            result.used_recovery_code,
        )
        self.currency_amount = ""
        self._clear_currency_step_up_fields()
        self._clear_rate_limit(persistence, "admin_currency_update", str(target_user.id))
        await self._load_user_data()
        self.force_refresh()

    def _on_currency_mode_toggle(self, event: rio.SwitchChangeEvent) -> None:
        """Toggle between adjust and set modes."""
        self.currency_mode_is_set = event.is_on
        self.force_refresh()

    def _on_create_verified_toggle(self, event: rio.SwitchChangeEvent) -> None:
        self.create_user_is_verified = event.is_on
        self.force_refresh()

    def _on_create_password_change(self, event: rio.TextInputChangeEvent) -> None:
        self.create_user_password = event.text
        self.create_user_password_strength = get_password_strength(event.text)
        self.create_user_acknowledge_weak_password = False
        self.force_refresh()

    def _on_create_role_change(self, event: rio.DropdownChangeEvent) -> None:
        self.create_user_role = event.value
        self._clear_create_step_up_fields()
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

    def _build_inline_step_up_action_inputs(
        self,
        *,
        password_binding: t.Any,
        two_factor_binding: t.Any,
        on_submit: t.Callable[..., t.Any],
        button_label: str,
        show_credentials: bool,
        show_unavailable_message: bool,
    ) -> list[rio.Component]:
        inputs: list[rio.Component] = []
        unavailable_message = self._step_up_unavailable_message()

        if show_credentials:
            if unavailable_message:
                if show_unavailable_message:
                    inputs.append(
                        rio.Banner(text=unavailable_message, style="danger")
                    )
            elif self.current_user and self.current_user.auth_provider == "password":
                inputs.append(
                    rio.TextInput(
                        label="Your Password",
                        text=password_binding,
                        is_secret=True,
                        on_confirm=on_submit,
                    )
                )

            if (
                not unavailable_message
                and self.current_user
                and self.current_user.two_factor_enabled
            ):
                inputs.append(
                    rio.TextInput(
                        label="2FA or Recovery Code",
                        text=two_factor_binding,
                        is_secret=True,
                        on_confirm=on_submit,
                    )
                )

        inputs.append(
            rio.Button(
                button_label,
                on_press=on_submit,
                shape="rounded",
            )
        )
        return inputs

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
        step_up_unavailable_message = self._step_up_unavailable_message()
        currency_step_up_active = bool(
            (self.currency_user_identifier or "").strip()
            or (self.currency_amount or "").strip()
        )
        delete_step_up_active = bool(
            (self.delete_user_identifier or "").strip()
            or (self.delete_user_confirmation or "").strip()
        )
        create_step_up_required = self._create_user_step_up_required()
        active_step_up_active = bool(
            (self.active_user_identifier or "").strip()
            or (self.active_user_confirmation or "").strip()
        )
        reset_step_up_active = bool((self.reset_user_identifier or "").strip())

        create_step_up_inputs = self._build_inline_step_up_action_inputs(
            password_binding=self.bind().create_user_step_up_password,
            two_factor_binding=self.bind().create_user_step_up_2fa,
            on_submit=self._on_create_user_pressed,
            button_label="Create User",
            show_credentials=create_step_up_required,
            show_unavailable_message=create_step_up_required,
        )
        active_step_up_inputs = self._build_inline_step_up_action_inputs(
            password_binding=self.bind().active_user_step_up_password,
            two_factor_binding=self.bind().active_user_step_up_2fa,
            on_submit=self._on_set_active_pressed,
            button_label="Apply Status",
            show_credentials=True,
            show_unavailable_message=active_step_up_active,
        )
        reset_step_up_inputs = self._build_inline_step_up_action_inputs(
            password_binding=self.bind().reset_user_step_up_password,
            two_factor_binding=self.bind().reset_user_step_up_2fa,
            on_submit=self._on_send_reset_pressed,
            button_label="Send Reset Email",
            show_credentials=True,
            show_unavailable_message=reset_step_up_active,
        )

        edit_step_up_inputs: list[rio.Component] = []
        if self._edit_email_step_up_may_be_required():
            if step_up_unavailable_message:
                edit_step_up_inputs.append(
                    rio.Banner(
                        text=step_up_unavailable_message,
                        style="danger",
                    )
                )
            elif requires_step_up_password:
                edit_step_up_inputs.append(rio.TextInput(
                    label="Your Password",
                    text=self.bind().edit_user_step_up_password,
                    is_secret=True,
                    on_confirm=self._on_edit_user_pressed,
                ))
            if not step_up_unavailable_message and requires_step_up_2fa:
                edit_step_up_inputs.append(
                    rio.TextInput(
                        label="2FA or Recovery Code",
                        text=self.bind().edit_user_step_up_2fa,
                        is_secret=True,
                        on_confirm=self._on_edit_user_pressed,
                    )
                )

        currency_step_up_inputs: list[rio.Component] = []
        if step_up_unavailable_message and currency_step_up_active:
            currency_step_up_inputs.append(
                rio.Banner(
                    text=step_up_unavailable_message,
                    style="danger",
                )
            )
        elif requires_step_up_password:
            currency_step_up_inputs.append(rio.TextInput(
                label="Your Password",
                text=self.bind().currency_step_up_password,
                is_secret=True,
                on_confirm=self._on_currency_submit,
            ))
        if not step_up_unavailable_message and requires_step_up_2fa:
            currency_step_up_inputs.append(
                rio.TextInput(
                    label="2FA or Recovery Code",
                    text=self.bind().currency_step_up_2fa,
                    is_secret=True,
                    on_confirm=self._on_currency_submit,
                )
            )

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
        delete_step_up_notice = (
            rio.Banner(
                text=step_up_unavailable_message,
                style="danger",
                margin_top=1,
            )
            if step_up_unavailable_message and delete_step_up_active
            else rio.Spacer(min_height=0, grow_x=False, grow_y=False)
        )
        if not step_up_unavailable_message and requires_step_up_password:
            delete_user_inputs.append(rio.TextInput(
                label="Your Password",
                text=self.bind().delete_user_step_up_password,
                is_secret=True,
                on_confirm=self._on_delete_user_pressed,
            ))
        if not step_up_unavailable_message and requires_step_up_2fa:
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
        currency_step_up_row = (
            self._responsive_form_layout(
                *currency_step_up_inputs,
                proportions=[1] * len(currency_step_up_inputs),
            )
            if currency_step_up_inputs
            else rio.Spacer(min_height=0, grow_x=False, grow_y=False)
        )
        create_step_up_row = self._responsive_form_layout(
            *create_step_up_inputs,
            proportions=[1] * len(create_step_up_inputs),
        )
        active_step_up_row = self._responsive_form_layout(
            *active_step_up_inputs,
            proportions=[1] * len(active_step_up_inputs),
        )
        reset_step_up_row = self._responsive_form_layout(
            *reset_step_up_inputs,
            proportions=[1] * len(reset_step_up_inputs),
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
                    on_change=self._on_create_password_change,
                    on_confirm=self._on_create_user_pressed,
                ),
                rio.Dropdown(
                    label="Role",
                    options={
                        role: role
                        for role in get_manageable_roles(self.current_user.role)
                    },
                    selected_value=self.create_user_role,
                    on_change=self._on_create_role_change,
                ),
                rio.Row(
                    rio.Text("Verified"),
                    rio.Switch(
                        is_on=self.create_user_is_verified,
                        on_change=self._on_create_verified_toggle,
                    ),
                    spacing=1,
                ),
                proportions=[1, 1, 1],
            ),

            rio.Text(
                f"Password strength: {self.create_user_password_strength}, "
                f"{get_password_strength_status(self.create_user_password_strength)}",
                style=rio.TextStyle(
                    fill=get_password_strength_color(
                        self.create_user_password_strength
                    )
                ),
            ),
            rio.ProgressBar(
                progress=max(
                    0,
                    min(self.create_user_password_strength / 100, 1),
                ),
                color=get_password_strength_color(
                    self.create_user_password_strength
                ),
            ),
            *(
                [
                    rio.Row(
                        rio.Switch(
                            is_on=self.bind().create_user_acknowledge_weak_password,
                        ),
                        rio.Text(
                            "I acknowledge this temporary password is weak",
                            style=rio.TextStyle(
                                fill=rio.Color.from_rgb(1, 0.6, 0, srgb=True),
                            ),
                        ),
                        spacing=1,
                        align_x=0,
                    )
                ]
                if (
                    config.ALLOW_WEAK_PASSWORDS
                    and self.create_user_password
                    and self.create_user_password_strength
                    < config.MIN_PASSWORD_STRENGTH
                )
                else []
            ),

            create_step_up_row,

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

            self._responsive_form_layout(
                *edit_step_up_inputs,
                proportions=[1] * len(edit_step_up_inputs),
            ) if edit_step_up_inputs else rio.Spacer(min_height=0, grow_x=False, grow_y=False),

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
                proportions=[2, 1],
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

            active_step_up_row,

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
                proportions=[1],
            ),

            reset_step_up_row,

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

            currency_step_up_row,

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

            delete_step_up_notice,

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
