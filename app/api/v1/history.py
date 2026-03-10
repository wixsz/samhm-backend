import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.history import HistoryResponse
from app.security.rbac import require_permission
from app.services.history_service import build_history_response

logger = logging.getLogger("SAMHM.History")

router = APIRouter()


@router.get(
    "/me",
    response_model=HistoryResponse,
    summary="Current user analysis history",
)
def my_history(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("analyze_text")),
):
    response = build_history_response(db, user_id=current_user["id"], limit=limit)
    logger.info("History requested | user=%s limit=%s", current_user["email"], limit)
    return response
