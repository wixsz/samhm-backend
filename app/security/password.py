from passlib.context import CryptContext

# bcrypt only supports passwords up to 72 bytes
BCRYPT_MAX_BYTES = 72

# Create password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _truncate_password(password: str) -> str:
    """
    Ensure password does not exceed bcrypt 72-byte limit.
    Uses byte length (not character length) to handle Unicode safely.
    """
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > BCRYPT_MAX_BYTES:
        password_bytes = password_bytes[:BCRYPT_MAX_BYTES]
    return password_bytes.decode("utf-8", errors="ignore")


def get_password_hash(password: str) -> str:
    """
    Hash a plain-text password using bcrypt safely.

    Args:
        password (str): The user's plain password.

    Returns:
        str: Secure bcrypt hashed password.
    """
    safe_password = _truncate_password(password)
    return pwd_context.hash(safe_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a bcrypt hashed password.

    Args:
        plain_password (str): Password entered by user.
        hashed_password (str): Stored bcrypt hash.

    Returns:
        bool: True if match, False otherwise.
    """
    safe_password = _truncate_password(plain_password)
    return pwd_context.verify(safe_password, hashed_password)
