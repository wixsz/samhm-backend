from datetime import datetime, timedelta
from typing import Dict, Optional
import uuid
import time
from collections import defaultdict

from jose import jwt, JWTError
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.config import settings
from app.db.models import User
from app.db.session import get_db
from app.security.token_blacklist import is_token_revoked, revoke_token
from app.core.security_logger import security_log

# =====================================================
# OAuth2 Scheme
# =====================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# =====================================================
# JWT Constants
# =====================================================
JWT_ISSUER = "SAMHM_API"
JWT_AUDIENCE = "SAMHM_USERS"


# =====================================================
# Create Token
# =====================================================
def create_access_token(data: Dict) -> str:
    """
    Generates hardened JWT access token.
    """
    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4()),
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
        }
    )

    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


# =====================================================
# Decode Token
# =====================================================
def decode_access_token(token: str) -> Dict:
    """
    Decodes and validates JWT token.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        return payload

    except JWTError:
        security_log(event="invalid_token_attempt")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )


# =====================================================
# Get Current User
# =====================================================
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Dict:
    """
    Extract authenticated user from JWT.
    """

    if is_token_revoked(token):
        security_log(event="revoked_token_used")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked"
        )

    payload = decode_access_token(token)

    email: Optional[str] = payload.get("sub")
    if email is None:
        security_log(event="invalid_token_payload")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()

    if user is None or not user.is_active:
        security_log(event="inactive_or_missing_user", user=email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    role_name = user.role.name if user.role else (payload.get("role") or "user")

    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "role": role_name,
    }


# =====================================================
# Logout Helper
# =====================================================
def revoke_current_token(token: str):
    """
    Revokes current JWT until expiration.
    """

    payload = decode_access_token(token)
    exp = payload.get("exp")

    if exp:
        remaining = exp - int(datetime.utcnow().timestamp())

        if remaining > 0:
            revoke_token(token, remaining)
            security_log(event="token_revoked")


# =====================================================
# Intrusion Detection Middleware
# =====================================================

request_tracker: Dict[str, list] = defaultdict(list)

MAX_REQUESTS = 100
WINDOW_SECONDS = 10


def get_real_ip(request: Request) -> str:
    """
    Get real client IP even behind nginx/docker proxy
    """
    forwarded = request.headers.get("x-forwarded-for")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host


async def intrusion_detection_middleware(request: Request, call_next):
    """
    Detect request flooding / suspicious traffic.
    Docker + nginx safe.
    """

    path = request.url.path

    # -------------------------------------------------
    # SAFE ENDPOINT WHITELIST (never block these)
    # -------------------------------------------------
    if path in ["/api/v1/health", "/docs", "/openapi.json", "/favicon.ico"]:
        return await call_next(request)

    ip = get_real_ip(request)
    now = time.time()

    request_tracker[ip].append(now)

    # keep recent timestamps only
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t < WINDOW_SECONDS]

    # -------------------------------------------------
    # RATE LIMIT DETECTION
    # -------------------------------------------------
    if len(request_tracker[ip]) > MAX_REQUESTS:
        security_log(
            event="possible_ddos_detected",
            ip=ip,
            request_count=len(request_tracker[ip]),
        )

        raise HTTPException(
            status_code=429, detail="Too many requests — temporarily blocked"
        )

    return await call_next(request)
