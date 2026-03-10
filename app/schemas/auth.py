from pydantic import BaseModel, Field, field_validator
from typing import Optional


# ======================================================
# Login Request Schema
# ======================================================
class LoginRequest(BaseModel):
    """
    Schema used for user login requests.
    """

    email: str = Field(
        ...,
        description="Registered user email address",
        example="user@example.com",
    )
    password: str = Field(
        ...,
        min_length=6,
        max_length=128,
        description="User password (plain text)",
        example="strongpassword123",
    )


class RegisterRequest(BaseModel):
    full_name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="User full name",
        example="John Doe",
    )
    email: str = Field(
        ...,
        description="User email address",
        example="user@example.com",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="User password",
        example="StrongPassword123",
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if "@" not in cleaned or cleaned.startswith("@") or cleaned.endswith("@"):
            raise ValueError("Invalid email address.")
        return cleaned


class RegisterResponse(BaseModel):
    id: str = Field(..., description="Created user identifier")
    email: str = Field(..., description="Registered email")
    full_name: str = Field(..., description="Registered full name")
    role: str = Field(..., description="Assigned role")
    message: str = Field(..., description="Registration status message")


# ======================================================
# Token Response Schema
# ======================================================
class TokenResponse(BaseModel):
    """
    Schema returned after successful authentication.
    """

    access_token: str = Field(
        ...,
        description="JWT access token",
    )
    token_type: str = Field(
        default="bearer",
        description="Authentication scheme",
        example="bearer",
    )
    expires_in: int = Field(
        ...,
        description="Token expiration time in seconds",
        example=3600,
    )


# ======================================================
# Token Payload (Decoded JWT)
# ======================================================
class TokenPayload(BaseModel):
    """
    Internal schema representing decoded JWT payload.
    """

    sub: str = Field(
        ...,
        description="Subject identifier (user email or user ID)",
        example="user@example.com",
    )
    exp: int = Field(
        ...,
        description="Expiration timestamp (UNIX)",
        example=1770620945,
    )


# ======================================================
# Authenticated User (Injected via Depends)
# ======================================================
class CurrentUser(BaseModel):
    """
    Schema representing the currently authenticated user.
    """

    id: str = Field(
        ...,
        description="Authenticated user identifier",
    )
    email: str = Field(
        ...,
        description="Authenticated user email",
    )
    full_name: Optional[str] = Field(
        default=None,
        description="Authenticated user's display name",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the user account is active",
    )
    role: str = Field(
        default="user",
        description="User role (e.g., user, admin)",
        example="user",
    )
