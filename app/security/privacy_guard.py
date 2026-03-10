import hashlib

from app.core.config import settings

# =====================================================
# Security Constant (Salt)
# =====================================================
SALT = settings.TEXT_HASH_SALT


# =====================================================
# Hash Text
# =====================================================
def hash_text(text: str) -> str:
    """
    Returns salted SHA256 hash of text.
    Prevents reverse lookup and rainbow table attacks.
    """
    return hashlib.sha256((text + SALT).encode("utf-8")).hexdigest()


# =====================================================
# Metadata Builder
# =====================================================
def hash_metadata(text: str):
    """
    Returns privacy-safe metadata.
    No raw text is stored.
    """
    return {
        "hash": hash_text(text),
        "length": len(text),
        "word_count": len(text.split()),
    }
