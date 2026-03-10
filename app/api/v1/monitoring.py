from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
import logging

from app.core.security import get_current_user
from app.monitoring.engine import metrics_engine
from app.monitoring.health import system_health

router = APIRouter()
logger = logging.getLogger("SAMHM.Monitoring")


# =========================================================
# ADMIN AUTHORIZATION DEPENDENCY
# =========================================================
def require_admin(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Allows access only to admin users.
    """

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    if user.get("role") != "admin":
        logger.warning("Unauthorized monitoring access attempt | user=%s", user)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )

    return user


# =========================================================
# METRICS ENDPOINT
# =========================================================
@router.get(
    "/metrics",
    summary="System metrics",
    description="Returns real-time API performance metrics.",
)
def metrics(user: Dict[str, Any] = Depends(require_admin)):
    try:
        return {"status": "ok", "metrics": metrics_engine.snapshot()}
    except Exception:
        logger.exception("Metrics endpoint failed")
        raise HTTPException(status_code=500, detail="Failed to retrieve metrics")


# =========================================================
# HEALTH STATUS ENDPOINT
# =========================================================
@router.get(
    "/health", summary="System health", description="Returns system health diagnostics."
)
def health(user: Dict[str, Any] = Depends(require_admin)):
    try:
        return {"status": "ok", "system": system_health()}
    except Exception:
        logger.exception("Health check failed")
        raise HTTPException(status_code=500, detail="Health check failed")
