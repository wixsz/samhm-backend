from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.security.rbac import require_permission
import logging
from typing import Any, Dict
from app.security.security_events import (
    get_all_events,
    get_events_by_type,
    get_attack_summary,
    get_suspicious_ips,
)

logger = logging.getLogger("SAMHM.SecurityDashboard")

router = APIRouter()


# =========================================================
# Response Formatter (Consistent API Responses)
# =========================================================
def success(data: Any) -> Dict:
    return {"status": "success", "data": data}


# =========================================================
# Get All Security Events
# Permission: view_security
# =========================================================
@router.get(
    "/events",
    summary="Retrieve all security events",
    description="Returns complete security event logs for monitoring and auditing.",
)
def all_events(
    limit: int = Query(100, ge=1, le=1000),
    user: Dict = Depends(require_permission("view_security")),
) -> Dict:

    events = get_all_events()[:limit]

    logger.info("Security dashboard accessed events | user=%s", user["email"])

    return success(events)


# =========================================================
# Filter Events By Type
# =========================================================
@router.get("/events/{event_type}", summary="Filter events by type")
def events_by_type(
    event_type: str,
    limit: int = Query(100, ge=1, le=1000),
    user: Dict = Depends(require_permission("view_security")),
) -> Dict:

    results = get_events_by_type(event_type)[:limit]

    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No events found for this type",
        )

    logger.info(
        "Security events filtered | type=%s | user=%s", event_type, user["email"]
    )

    return success(results)


# =========================================================
# Attack Summary Statistics
# =========================================================
@router.get("/summary", summary="Get security attack summary")
def attack_summary(user: Dict = Depends(require_permission("view_security"))) -> Dict:

    summary = get_attack_summary()

    logger.info("Security summary accessed | user=%s", user["email"])

    return success(summary)


# =========================================================
# Suspicious IP Detection
# =========================================================
@router.get("/suspicious-ips", summary="Get suspicious IP list")
def suspicious_ips(
    threshold: int = Query(5, ge=1, le=100),
    user: Dict = Depends(require_permission("view_security")),
) -> Dict:

    ips = get_suspicious_ips(threshold)

    logger.warning(
        "Suspicious IP report generated | user=%s | threshold=%s",
        user["email"],
        threshold,
    )

    return success({"count": len(ips), "ips": ips})


# =========================================================
# Health Check for Security Engine
# =========================================================
@router.get("/status", summary="Security system status")
def security_status(user: Dict = Depends(require_permission("view_security"))) -> Dict:

    return success(
        {
            "engine": "running",
            "events_loaded": len(get_all_events()),
            "status": "operational",
        }
    )
