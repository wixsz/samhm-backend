import time
import logging
from collections import deque
from fastapi import Request

logger = logging.getLogger("SAMHM.Alerting")

# Sliding windows
ERROR_WINDOW = deque(maxlen=50)
AUTH_FAIL_WINDOW = deque(maxlen=50)
REQUEST_WINDOW = deque(maxlen=200)

ALERT_THRESHOLD_ERRORS = 10
ALERT_THRESHOLD_AUTH = 15
ALERT_THRESHOLD_RPS = 100
ALERT_THRESHOLD_SLOW = 2.0


def trigger_alert(reason: str, value: int) -> None:
    logger.critical("SECURITY ALERT | %s | value=%s", reason, value)


async def alerting_middleware(request: Request, call_next):
    start = time.time()

    response = await call_next(request)

    duration = time.time() - start
    status = response.status_code
    now = time.time()

    REQUEST_WINDOW.append(now)

    # High error rate
    if status >= 500:
        ERROR_WINDOW.append(now)
        if len(ERROR_WINDOW) >= ALERT_THRESHOLD_ERRORS:
            trigger_alert("High server error rate", len(ERROR_WINDOW))
            ERROR_WINDOW.clear()

    # Brute-force detection
    if status in (401, 403):
        AUTH_FAIL_WINDOW.append(now)
        if len(AUTH_FAIL_WINDOW) >= ALERT_THRESHOLD_AUTH:
            trigger_alert("Brute force attempt detected", len(AUTH_FAIL_WINDOW))
            AUTH_FAIL_WINDOW.clear()

    # Traffic spike detection
    if len(REQUEST_WINDOW) >= ALERT_THRESHOLD_RPS:
        trigger_alert("Traffic spike detected", len(REQUEST_WINDOW))
        REQUEST_WINDOW.clear()

    # Slow request detection
    if duration > ALERT_THRESHOLD_SLOW:
        logger.warning(
            "Slow request detected | path=%s | duration=%.3fs",
            request.url.path,
            duration,
        )

    return response
