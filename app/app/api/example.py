from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

from app.api.auth_dependencies import get_persistence
from app.persistence import Persistence
from app.request_context import context_from_fastapi_request
from app.rate_limits import contact_ip_policy, rate_limit_key, rate_limited_message
from app.scripts.message_utils import create_contact_submission

router = APIRouter()


class ContactRequest(BaseModel):
    name: str
    email: EmailStr
    message: str


@router.get("/api/test")
def test_route():
    return {"message": "Hello, World!"}


@router.post("/api/contact", status_code=201)
async def save_contact(
    payload: ContactRequest,
    request: Request,
    db: Persistence = Depends(get_persistence),
) -> Dict[str, Any]:
    """Accept contact form submissions from the frontend."""
    context = context_from_fastapi_request(request, identifier=payload.email)
    decision = db.check_rate_limit(
        policy=contact_ip_policy(),
        key=rate_limit_key("ip", context.client_ip),
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_limited_message(
                "Too many contact form submissions.",
                decision.retry_after_seconds,
            ),
            headers={"Retry-After": str(decision.retry_after_seconds or 1)},
        )

    return create_contact_submission(
        name=payload.name,
        email=payload.email,
        message=payload.message,
    )
