import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.dashboard import DashboardSummary
from app.security.rbac import require_permission
from app.services.dashboard_service import build_dashboard_summary

logger = logging.getLogger("SAMHM.Dashboard")

router = APIRouter()


@router.get(
    "/user-summary",
    response_model=DashboardSummary,
    summary="Current user dashboard summary",
)
def user_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("analyze_text")),
):
    summary = build_dashboard_summary(db, days=days, user_id=current_user["id"])
    logger.info("User dashboard summary requested | user=%s days=%s", current_user["email"], days)
    return summary


@router.get(
    "/admin-summary",
    response_model=DashboardSummary,
    summary="Administrative dashboard summary",
)
def admin_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    summary = build_dashboard_summary(db, days=days)
    logger.info(
        "Admin dashboard summary requested | user=%s days=%s",
        current_user["email"],
        days,
    )
    return summary
