from datetime import datetime, timedelta

# In-memory store (replace with Redis later for production)
BLACKLIST = {}


def revoke_token(token: str, expires_in: int):
    """
    Adds token to blacklist until expiration time.
    """
    BLACKLIST[token] = datetime.utcnow() + timedelta(seconds=expires_in)


def is_token_revoked(token: str) -> bool:
    """
    Checks if token exists and is still revoked.
    """
    if token in BLACKLIST:

        # auto cleanup expired entries
        if datetime.utcnow() > BLACKLIST[token]:
            del BLACKLIST[token]
            return False

        return True

    return False
