import time
from collections import defaultdict

from app.core.config import settings

MAX_ATTEMPTS = 5
LOCK_TIME = 300  # seconds

failed_attempts = defaultdict(int)
lock_until = {}


def _locking_enabled() -> bool:
    return settings.APP_ENV.lower() == "production"


def is_locked(identifier: str):
    """
    Checks if user is locked.
    """
    if not _locking_enabled():
        return False

    if identifier in lock_until:

        if time.time() < lock_until[identifier]:
            return True

        # unlock automatically after time
        del lock_until[identifier]
        failed_attempts[identifier] = 0

    return False


def record_failure(identifier: str):
    """
    Records failed login attempt.
    """
    if not _locking_enabled():
        return False

    failed_attempts[identifier] += 1

    if failed_attempts[identifier] >= MAX_ATTEMPTS:
        lock_until[identifier] = time.time() + LOCK_TIME
        return True

    return False


def reset_attempts(identifier: str):
    """
    Clears failure counter on success.
    """

    failed_attempts[identifier] = 0
