from fastapi import Depends, HTTPException
from app.core.security import get_current_user

# =========================================================
# ROLE → PERMISSIONS MAP
# =========================================================

ROLE_PERMISSIONS = {
    "admin": {
        "view_security",
        "view_metrics",
        "manage_users",
        "delete_data",
        "analyze_text",
    },
    "analyst": {"view_metrics", "analyze_text"},
    "security": {"view_security", "view_metrics"},
    "user": {"analyze_text"},
}


# =========================================================
# Permission Checker Dependency
# =========================================================


def require_permission(permission: str):

    def checker(user=Depends(get_current_user)):

        role = user.get("role")

        if role not in ROLE_PERMISSIONS:
            raise HTTPException(403, "Invalid role")

        if permission not in ROLE_PERMISSIONS[role]:
            raise HTTPException(403, "Permission denied")

        return user

    return checker
