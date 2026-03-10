import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.models import AuditLog, Role, User
from app.db.session import get_db
from app.schemas.admin import (
    AdminConsoleResponse,
    AdminUserActionResponse,
    AdminUserUpdateRequest,
)
from app.services.admin_service import build_admin_console_response

logger = logging.getLogger("SAMHM.Admin")

router = APIRouter()
ALLOWED_ROLE_NAMES = {"admin", "analyst", "security", "user"}


def require_admin_console_access(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def _count_active_admins(db: Session) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(User)
            .join(Role, User.role_id == Role.id)
            .where(Role.name == "admin", User.is_active.is_(True))
        )
        or 0
    )


def _get_role_name(db: Session, role_id: str) -> str:
    role_name = db.scalar(select(Role.name).where(Role.id == role_id))
    return role_name or "user"


@router.get(
    "/console",
    response_model=AdminConsoleResponse,
    summary="Admin BI console data",
)
def admin_console(
    log_limit: int = Query(50, ge=10, le=200),
    user_limit: int = Query(100, ge=10, le=200),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin_console_access),
):
    logger.info(
        "Admin console requested | user=%s log_limit=%s user_limit=%s",
        current_user["email"],
        log_limit,
        user_limit,
    )
    return build_admin_console_response(
        db,
        current_user_id=current_user["id"],
        log_limit=log_limit,
        user_limit=user_limit,
    )


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserActionResponse,
    summary="Update admin-managed user attributes",
)
def update_user(
    user_id: str,
    payload: AdminUserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin_console_access),
):
    if payload.full_name is None and payload.role is None and payload.is_active is None:
        raise HTTPException(status_code=400, detail="No updates provided.")

    target_user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    current_role = _get_role_name(db, target_user.role_id)
    next_role_name = current_role
    next_is_active = target_user.is_active if payload.is_active is None else payload.is_active

    role_obj = None
    if payload.role is not None:
        normalized_role = payload.role.strip().lower()
        if normalized_role not in ALLOWED_ROLE_NAMES:
            raise HTTPException(status_code=400, detail="Invalid role.")

        role_obj = db.execute(select(Role).where(Role.name == normalized_role)).scalar_one_or_none()
        if role_obj is None:
            raise HTTPException(status_code=500, detail=f"Role '{normalized_role}' is not configured.")
        next_role_name = normalized_role

    if target_user.id == current_user["id"] and next_is_active is False:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")

    is_removing_admin_privilege = current_role == "admin" and next_role_name != "admin"
    is_deactivating_admin = current_role == "admin" and target_user.is_active and next_is_active is False
    if is_removing_admin_privilege or is_deactivating_admin:
        if _count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail="At least one active admin is required.")

    old_values = {
        "full_name": target_user.full_name,
        "role": current_role,
        "is_active": target_user.is_active,
    }

    if payload.full_name is not None:
        cleaned_name = payload.full_name.strip()
        target_user.full_name = cleaned_name or (target_user.email.split("@")[0] if target_user.email else "User")

    if role_obj is not None:
        target_user.role_id = role_obj.id

    if payload.is_active is not None:
        target_user.is_active = payload.is_active

    new_role = _get_role_name(db, target_user.role_id)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="admin_update_user",
            entity_type="user",
            entity_id=target_user.id,
            outcome="success",
            details={
                "target_email": target_user.email,
                "changes": {
                    "old": old_values,
                    "new": {
                        "full_name": target_user.full_name,
                        "role": new_role,
                        "is_active": target_user.is_active,
                    },
                },
            },
        )
    )
    db.commit()
    db.refresh(target_user)

    return AdminUserActionResponse(
        id=target_user.id,
        full_name=target_user.full_name or target_user.email.split("@")[0],
        email=target_user.email,
        role=new_role,
        status="active" if target_user.is_active else "inactive",
        message="User updated successfully.",
    )


@router.delete(
    "/users/{user_id}",
    response_model=AdminUserActionResponse,
    summary="Remove user from platform access (soft remove)",
)
def remove_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin_console_access),
):
    target_user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    if target_user.id == current_user["id"]:
        raise HTTPException(status_code=400, detail="You cannot remove your own account.")

    target_role = _get_role_name(db, target_user.role_id)
    if target_role == "admin" and target_user.is_active and _count_active_admins(db) <= 1:
        raise HTTPException(status_code=400, detail="At least one active admin is required.")

    target_user.is_active = False

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="admin_remove_user",
            entity_type="user",
            entity_id=target_user.id,
            outcome="success",
            details={
                "target_email": target_user.email,
                "note": "Soft remove applied by setting account inactive.",
            },
        )
    )
    db.commit()
    db.refresh(target_user)

    return AdminUserActionResponse(
        id=target_user.id,
        full_name=target_user.full_name or target_user.email.split("@")[0],
        email=target_user.email,
        role=target_role,
        status="inactive",
        message="User removed from access (account deactivated).",
    )
