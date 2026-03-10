import time
from collections import defaultdict, deque
from fastapi import Request
from app.core.security_logger import security_log
from fastapi.responses import JSONResponse
from app.core.config import settings

# ================================
# Detection thresholds
# ================================

MAX_REQUESTS = 60
WINDOW = 10

LOGIN_LIMIT = 10
SCAN_LIMIT = 15

BLOCK_TIME = 300


# ================================
# Storage
# ================================

request_log = defaultdict(deque)
blocked_ips = {}
login_attempts = defaultdict(int)
path_access = defaultdict(lambda: defaultdict(int))


def _is_local_dev_request(ip: str) -> bool:
    return settings.APP_ENV.lower() != "production" and ip in {"127.0.0.1", "::1", "localhost"}


# ================================
# Detection Middleware
# ================================


async def intrusion_detection_middleware(request: Request, call_next):

    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    now = time.time()

    # Keep local development smooth: don't self-block localhost traffic.
    if _is_local_dev_request(ip):
        return await call_next(request)

    # -------------------------
    # Check blocked IP
    # -------------------------
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            security_log(event="blocked_ip_attempt", ip=ip)
            return JSONResponse(status_code=403, content={"detail": "Access denied"})
        else:
            del blocked_ips[ip]

    # -------------------------
    # Track requests
    # -------------------------
    q = request_log[ip]
    q.append(now)

    while q and now - q[0] > WINDOW:
        q.popleft()

    # -------------------------
    # Rate attack detection
    # -------------------------
    if len(q) > MAX_REQUESTS:
        blocked_ips[ip] = now + BLOCK_TIME

        security_log(event="dos_detected", ip=ip, requests=len(q))

        return JSONResponse(status_code=429, content={"detail": "Too many requests"})

    # -------------------------
    # Login brute force detection
    # -------------------------
    if request.method.upper() == "POST" and "login" in path.lower():
        login_attempts[ip] += 1

        if login_attempts[ip] > LOGIN_LIMIT:
            blocked_ips[ip] = now + BLOCK_TIME

            security_log(
                event="bruteforce_detected", ip=ip, attempts=login_attempts[ip]
            )

            return JSONResponse(status_code=403, content={"detail": "Blocked"})

    # -------------------------
    # Endpoint scanning detection
    # -------------------------
    path_access[ip][path] += 1

    if len(path_access[ip]) > SCAN_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME

        security_log(event="endpoint_scan_detected", ip=ip, paths=len(path_access[ip]))

        return JSONResponse(status_code=403, content={"detail": "Scanner detected"})

    # -------------------------
    # Continue request
    # -------------------------
    response = await call_next(request)
    return response
