from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, EmailStr

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
async def save_contact(request: ContactRequest) -> Dict[str, Any]:
    """Accept contact form submissions from the frontend."""
    return create_contact_submission(
        name=request.name,
        email=request.email,
        message=request.message,
    )
