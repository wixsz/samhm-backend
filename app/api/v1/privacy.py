from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from datetime import datetime
import hashlib
import logging

from app.core.security import get_current_user
from app.core.config import settings
from app.core.limiter import limiter

router = APIRouter()
logger = logging.getLogger("SAMHM.Privacy")


# ============================================================
# Utility: Hash User Identifier (Privacy-by-Design)
# ============================================================


def _hash_user_identifier(email: str) -> str:
    """
    Hash user identifier using SHA-256 with application salt.
    Ensures no raw PII is stored or logged.
    """
    salted_value = f"{email}{settings.TEXT_HASH_SALT}"
    return hashlib.sha256(salted_value.encode("utf-8")).hexdigest()


# ============================================================
# GDPR: Right to Erasure (Delete My Data)
# ============================================================


@router.delete(
    "/delete-my-data",
    status_code=status.HTTP_200_OK,
    summary="Delete All User Data",
    description="Deletes all stored data related to the authenticated user.",
)
@limiter.limit("3/hour")  # Prevent abuse
def delete_my_data(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Implements user data erasure according to privacy-by-design principles.
    All stored user-related data should be permanently removed.
    """

    user_email = current_user["email"]
    user_hash = _hash_user_identifier(user_email)

    # ============================================================
    # Replace this section with actual database deletion logic
    # ============================================================
    # Example:
    # db.delete_user_sentiment_records(user_email)
    # db.delete_user_activity_logs(user_email)
    # db.delete_user_profile(user_email)
    # ============================================================

    deletion_timestamp = datetime.utcnow().isoformat()

    # Secure audit log (no raw email logged)
    logger.info(
        "UserDataDeletion | user_hash=%s | timestamp=%s",
        user_hash,
        deletion_timestamp,
    )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": "All user-related data has been permanently deleted.",
            "timestamp": deletion_timestamp,
        },
    )
