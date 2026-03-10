from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.security.password import get_password_hash, verify_password
from app.core.security import create_access_token
from app.db.models import Role, RoleName, User
from app.db.session import get_db
from app.security.login_guard import is_locked, record_failure, reset_attempts
from app.core.security_logger import security_log
from app.schemas.auth import RegisterRequest, RegisterResponse, TokenResponse

logger = logging.getLogger("SAMHM.Auth")

router = APIRouter()


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register_user(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    email = payload.email.strip().lower()
    full_name = payload.full_name.strip()

    existing_user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    default_role = db.execute(
        select(Role).where(Role.name == RoleName.USER.value)
    ).scalar_one_or_none()
    if default_role is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user role is not configured.",
        )

    user = User(
        email=email,
        password_hash=get_password_hash(payload.password),
        full_name=full_name,
        role_id=default_role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("User registered | email=%s", email)

    return RegisterResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name or full_name,
        role=default_role.name,
        message="Account created successfully.",
    )


# =========================================================
# LOGIN ENDPOINT
# =========================================================
@router.post("/login", response_model=TokenResponse, summary="Authenticate user")
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):

    identifier = form_data.username.strip().lower()
    ip = request.client.host if request.client else "unknown"

    logger.info("Login attempt | user=%s | ip=%s", identifier, ip)

    # ---------------- LOCK CHECK ----------------
    if is_locked(identifier):
        security_log(event="locked_attempt", user=identifier, ip=ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Account temporarily locked"
        )

    user = db.execute(select(User).where(User.email == identifier)).scalar_one_or_none()

    # ---------------- USER CHECK ----------------
    if user is None:
        record_failure(identifier)
        security_log(event="invalid_user", user=identifier, ip=ip)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---------------- PASSWORD CHECK ----------------
    if not user.is_active:
        security_log(event="inactive_user_login_attempt", user=identifier, ip=ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # ---------------- PASSWORD CHECK ----------------
    if not verify_password(form_data.password, user.password_hash):
        record_failure(identifier)
        security_log(event="wrong_password", user=identifier, ip=ip)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ---------------- SUCCESS ----------------
    reset_attempts(identifier)

    user.last_login_at = datetime.utcnow()
    db.add(user)
    db.commit()

    payload = {
        "sub": user.email,
        "role": user.role.name if user.role else "user",
        "user_id": user.id,
    }

    token = create_access_token(payload)

    logger.info("Login success | user=%s", identifier)

    return {"access_token": token, "token_type": "bearer", "expires_in": 3600}
