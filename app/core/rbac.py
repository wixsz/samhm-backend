from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user


def require_role(*allowed_roles: str):
    """
    Enforce role-based access control for protected endpoints.
    """

    def checker(user: dict = Depends(get_current_user)):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return checker
