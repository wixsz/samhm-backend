import re
from fastapi import Request
from fastapi.responses import JSONResponse

# =========================================================
# SAFE PATHS (must bypass firewall)
# =========================================================
SAFE_PREFIXES = (
    "/",
    "/docs",
    "/openapi",
    "/redoc",
    "/api/v1/health",
)

# =========================================================
# MALICIOUS PATTERNS
# tuned to reduce false positives
# =========================================================
BLOCK_PATTERNS = [
    r"\b(union\s+select|select\s+\*|drop\s+table|insert\s+into)\b",  # SQLi
    r"<script.*?>.*?</script.*?>",  # XSS
    r"(;|\|\||&&)\s*(ls|cat|bash|sh|cmd|powershell)",  # command injection
    r"(\.\./|\.\.\\)",  # path traversal
    r"\b(wget|curl|powershell)\b",  # exploit tools
    r"\b(nmap|sqlmap|nikto|dirbuster)\b",  # scanners
]

compiled_patterns = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in BLOCK_PATTERNS]


# =========================================================
# FIREWALL MIDDLEWARE
# =========================================================
async def firewall_middleware(request: Request, call_next):

    path = request.url.path

    # -----------------------------------------------------
    # Allow safe endpoints immediately
    # -----------------------------------------------------
    if path.startswith(SAFE_PREFIXES):
        return await call_next(request)

    # -----------------------------------------------------
    # Collect request data safely
    # -----------------------------------------------------
    try:
        body_bytes = await request.body()
        body = body_bytes.decode(errors="ignore") if body_bytes else ""
    except Exception:
        body = ""

    query = request.url.query or ""

    headers = " ".join(f"{k}:{v}" for k, v in request.headers.items())

    combined = f"{path} {query} {headers} {body}"

    # -----------------------------------------------------
    # Pattern Detection
    # -----------------------------------------------------
    for pattern in compiled_patterns:
        if pattern.search(combined):
            return JSONResponse(
                status_code=403,
                content={"detail": "Request blocked by security firewall"},
            )

    # -----------------------------------------------------
    # Continue request if safe
    # -----------------------------------------------------
    response = await call_next(request)
    return response
