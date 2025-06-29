from fastapi import APIRouter

router = APIRouter()

@router.get("/api/test")
def test_route():
    return {"message": "Hello, World!"}
