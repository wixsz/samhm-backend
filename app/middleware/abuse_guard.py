import time
from fastapi import Request, HTTPException
from app.core.security_logger import security_log
from app.core.config import settings

MAX_REQUESTS = 30
WINDOW = 60
BLOCK_TIME = 300

requests_db = {}
blocked_ips = {}


def _is_local_dev_request(ip: str) -> bool:
    return settings.APP_ENV.lower() != "production" and ip in {
        "127.0.0.1",
        "::1",
        "localhost",
    }


async def abuse_guard_middleware(request: Request, call_next):

    ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Keep local development smooth: don't self-block localhost traffic.
    if _is_local_dev_request(ip):
        return await call_next(request)

    # already blocked
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            security_log(event="blocked_ip_attempt", ip=ip)
            raise HTTPException(403, "Too many requests. Temporarily blocked.")
        else:
            del blocked_ips[ip]

    # record request
    requests_db.setdefault(ip, [])
    requests_db[ip].append(now)

    # cleanup old timestamps
    requests_db[ip] = [t for t in requests_db[ip] if now - t < WINDOW]

    # detect abuse
    if len(requests_db[ip]) > MAX_REQUESTS:
        blocked_ips[ip] = now + BLOCK_TIME

        security_log(event="ip_blocked", ip=ip, requests=len(requests_db[ip]))

        raise HTTPException(429, "Rate limit exceeded. Temporarily blocked.")

    return await call_next(request)
