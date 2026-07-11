from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.auth_dependencies import (
    get_current_session,
    get_current_user,
    get_persistence,
    is_admin_or_root,
)
from app.permissions import can_manage_role
from app.currency import (
    attach_currency_name,
    format_minor_amount,
    get_currency_config,
    get_major_amount,
    major_to_minor,
)
from app.data_models import AppUser, CurrencyLedgerEntry, UserSession
from app.persistence import (
    AdminMutationContext,
    AdminSessionInvalidError,
    Persistence,
)
from app.rate_limits import rate_limit_key, rate_limited_message, sensitive_action_policy
from app.session_validation import verify_step_up_credentials
from app.validation import (
    CurrencyConfigResponse,
    CurrencyBalanceResponse,
    CurrencyLedgerEntryResponse,
    CurrencyAdjustmentRequest,
    CurrencySetBalanceRequest,
)

router = APIRouter()


@router.get("/api/currency/config", response_model=CurrencyConfigResponse)
async def get_currency_config_route() -> CurrencyConfigResponse:
    """
    Expose the current primary currency configuration to clients.
    """
    cfg = get_currency_config()
    return CurrencyConfigResponse(
        name=cfg.name,
        name_plural=cfg.name_plural,
        symbol=cfg.symbol,
        decimal_places=cfg.decimal_places,
        allow_negative=cfg.allow_negative,
    )


@router.get("/api/currency/balance", response_model=CurrencyBalanceResponse)
async def get_currency_balance_route(
    current_user: AppUser = Depends(get_current_user),
    db: Persistence = Depends(get_persistence),
) -> CurrencyBalanceResponse:
    """
    Retrieve the authenticated user's balance information.
    """
    overview = await db.get_currency_overview(current_user.id)
    formatted_with_label = attach_currency_name(
        overview["formatted"], quantity_minor_units=overview["balance_minor"]
    )
    updated_at = overview["updated_at"]

    return CurrencyBalanceResponse(
        balance_minor=overview["balance_minor"],
        balance_major=overview["balance_major"],
        formatted=overview["formatted"],
        label=overview["label"],
        formatted_with_label=formatted_with_label,
        updated_at=updated_at.timestamp() if isinstance(updated_at, datetime) else None,
    )


@router.get("/api/currency/ledger", response_model=List[CurrencyLedgerEntryResponse])
async def list_currency_ledger_route(
    limit: int = Query(50, ge=1, le=500),
    before: Optional[float] = Query(
        None, description="Unix timestamp; return entries created before this value."
    ),
    after: Optional[float] = Query(
        None, description="Unix timestamp; return entries created after this value."
    ),
    user_id: Optional[UUID] = Query(
        None,
        description="Optional user ID; requires admin/root privileges when targeting others.",
    ),
    current_user: AppUser = Depends(get_current_user),
    db: Persistence = Depends(get_persistence),
) -> List[CurrencyLedgerEntryResponse]:
    """
    Retrieve currency ledger entries. Non-admins may only access their own history.
    """
    target_user_id = user_id or current_user.id

    if target_user_id != current_user.id:
        if not is_admin_or_root(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges to view other users' ledger entries.",
            )
        target_user = await _resolve_target_user(target_user_id, None, db)
        _require_currency_target_access(
            current_user,
            target_user,
            action="view currency ledger entries for",
        )

    before_dt = datetime.fromtimestamp(before, tz=timezone.utc) if before else None
    after_dt = datetime.fromtimestamp(after, tz=timezone.utc) if after else None

    entries = await db.list_currency_ledger(
        target_user_id,
        limit=limit,
        before=before_dt,
        after=after_dt,
    )

    return [_serialize_ledger_entry(entry) for entry in entries]


@router.post(
    "/api/currency/adjust",
    response_model=CurrencyLedgerEntryResponse,
    status_code=status.HTTP_201_CREATED,
)
async def adjust_currency_route(
    payload: CurrencyAdjustmentRequest,
    current_session: UserSession = Depends(get_current_session),
    current_user: AppUser = Depends(get_current_user),
    db: Persistence = Depends(get_persistence),
) -> CurrencyLedgerEntryResponse:
    """
    Adjust a user's balance by a delta amount. Admin/root only.
    """
    if not is_admin_or_root(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only privileged users can adjust balances.",
        )

    target_user = await _resolve_target_user(payload.target_user_id, payload.target_identifier, db)
    _require_currency_target_access(
        current_user,
        target_user,
        action="update balances for",
    )
    await _require_step_up(payload, current_session, current_user, db)
    minor_delta = major_to_minor(payload.amount)

    try:
        entry = await db.admin_adjust_currency_balance(
            target_user.id,
            delta_minor=minor_delta,
            reason=payload.reason,
            metadata=payload.metadata,
            admin_context=AdminMutationContext(auth_token=current_session.id),
        )
    except AdminSessionInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found.",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return _serialize_ledger_entry(entry)


@router.post(
    "/api/currency/set",
    response_model=CurrencyLedgerEntryResponse,
    status_code=status.HTTP_201_CREATED,
)
async def set_currency_route(
    payload: CurrencySetBalanceRequest,
    current_session: UserSession = Depends(get_current_session),
    current_user: AppUser = Depends(get_current_user),
    db: Persistence = Depends(get_persistence),
) -> CurrencyLedgerEntryResponse:
    """
    Set a user's balance to an exact amount. Admin/root only.
    """
    if not is_admin_or_root(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only privileged users can set balances.",
        )

    target_user = await _resolve_target_user(payload.target_user_id, payload.target_identifier, db)
    _require_currency_target_access(
        current_user,
        target_user,
        action="update balances for",
    )
    await _require_step_up(payload, current_session, current_user, db)
    minor_amount = major_to_minor(payload.balance)

    try:
        entry = await db.admin_set_currency_balance(
            target_user.id,
            new_balance_minor=minor_amount,
            reason=payload.reason,
            metadata=payload.metadata,
            admin_context=AdminMutationContext(auth_token=current_session.id),
        )
    except AdminSessionInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found.",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return _serialize_ledger_entry(entry)


async def _require_step_up(
    payload: CurrencyAdjustmentRequest | CurrencySetBalanceRequest,
    current_session: UserSession,
    current_user: AppUser,
    db: Persistence,
) -> None:
    decision = db.check_rate_limit(
        policy=sensitive_action_policy("admin_step_up"),
        key=rate_limit_key("admin_step_up", current_user.id),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_limited_message(
                "Too many verification attempts.",
                decision.retry_after_seconds,
            ),
            headers={"Retry-After": str(decision.retry_after_seconds or 1)},
        )

    result = await verify_step_up_credentials(
        db,
        current_session,
        current_user,
        password=payload.step_up.password,
        two_factor_code=payload.step_up.two_factor_code,
    )
    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=result.error_message or "Verification failed.",
        )

    db.clear_rate_limit(
        scope=sensitive_action_policy("admin_step_up").scope,
        key=rate_limit_key("admin_step_up", current_user.id),
    )


def _require_currency_target_access(
    current_user: AppUser,
    target_user: AppUser,
    *,
    action: str,
) -> None:
    if current_user.id == target_user.id:
        return

    try:
        allowed = can_manage_role(current_user.role, target_user.role)
    except ValueError:
        allowed = False

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"You do not have permission to {action} users with "
                f"role {target_user.role}."
            ),
        )


async def _resolve_target_user(
    target_user_id: Optional[UUID],
    identifier: Optional[str],
    db: Persistence,
) -> AppUser:
    """
    Resolve the target user by UUID or identifier. Raises HTTP 404 if not found.
    """
    try:
        if target_user_id:
            return await db.get_user_by_id(target_user_id)
        if identifier:
            return await db.get_user_by_email_or_username(identifier)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found.",
        )

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Target user must be specified.",
    )


def _serialize_ledger_entry(entry: CurrencyLedgerEntry) -> CurrencyLedgerEntryResponse:
    """
    Convert a ledger dataclass into the API response model, adding formatted fields.
    """
    delta_formatted = format_minor_amount(entry.delta)
    delta_with_label = attach_currency_name(delta_formatted, quantity_minor_units=entry.delta)

    balance_formatted = format_minor_amount(entry.balance_after)
    balance_with_label = attach_currency_name(
        balance_formatted, quantity_minor_units=entry.balance_after
    )

    return CurrencyLedgerEntryResponse(
        id=entry.id,
        delta_minor=entry.delta,
        delta_major=float(get_major_amount(entry.delta)),
        delta_formatted=delta_formatted,
        delta_with_label=delta_with_label,
        balance_after_minor=entry.balance_after,
        balance_after_major=float(get_major_amount(entry.balance_after)),
        balance_after_formatted=balance_formatted,
        balance_after_with_label=balance_with_label,
        reason=entry.reason,
        metadata=entry.metadata,
        actor_user_id=entry.actor_user_id,
        created_at=entry.created_at.timestamp(),
    )
