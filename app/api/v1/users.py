from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.models import User
from app.db.session import get_db
from app.schemas.auth import CurrentUser

router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.get("/me", summary="Get current user")
def get_me(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.execute(select(User).where(User.id == current_user["id"])).scalar_one()
    role_name = user.role.name if user.role else current_user["role"]

    return CurrentUser(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        role=role_name,
    )
