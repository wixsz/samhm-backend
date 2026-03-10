import asyncio
import logging
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# =====================================================
# Internal Imports
# =====================================================
from app.api.v1 import (
    admin,
    auth,
    dashboard,
    history,
    privacy,
    reports,
    security_dashboard,
    sentiment,
    users,
)
from app.api.v1.debug import router as debug_router
from app.api.v1.monitoring import router as monitoring_router
from app.core.config import settings
from app.core.limiter import limiter
from app.core.logging_config import setup_logging
from app.db.session import initialize_database
from app.middleware.abuse_guard import abuse_guard_middleware
from app.middleware.alerting import alerting_middleware
from app.middleware.error_tracker import error_tracker_middleware
from app.middleware.observability import observability_middleware
from app.security.firewall import firewall_middleware
from app.security.intrusion_detection import intrusion_detection_middleware
from app.services.sentiment_service import SentimentService

# =====================================================
# Logging Setup
# =====================================================
setup_logging()
logger = logging.getLogger("SAMHM")

# =====================================================
# Constants
# =====================================================
API_PREFIX = "/api/v1"
MAX_BODY_SIZE = 1024 * 1024
MAX_BATCH_UPLOAD_BODY_SIZE = 12 * 1024 * 1024
DEFAULT_REQUEST_TIMEOUT_SECONDS = 15
BATCH_UPLOAD_TIMEOUT_SECONDS = 180

# =====================================================
# App Initialization
# =====================================================
app = FastAPI(
    title=settings.APP_NAME,
    description="Sentiment Analysis for Mental Health Monitoring API",
    version=settings.APP_VERSION,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.state.limiter = limiter

# =====================================================
# Timeout Protection
# =====================================================
@app.middleware("http")
async def timeout_middleware(request: Request, call_next: Callable):
    timeout_seconds = (
        BATCH_UPLOAD_TIMEOUT_SECONDS
        if request.url.path.endswith("/sentiment/batch-upload")
        else DEFAULT_REQUEST_TIMEOUT_SECONDS
    )
    try:
        return await asyncio.wait_for(call_next(request), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning("Timeout | path=%s", request.url.path)
        return JSONResponse(status_code=504, content={"detail": "Request timeout"})


# =====================================================
# Body Size Protection
# =====================================================
@app.middleware("http")
async def limit_body_size(request: Request, call_next: Callable):
    content_length = request.headers.get("content-length")
    max_size = (
        MAX_BATCH_UPLOAD_BODY_SIZE
        if request.url.path.endswith("/sentiment/batch-upload")
        else MAX_BODY_SIZE
    )

    if content_length and int(content_length) > max_size:
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})

    return await call_next(request)


# =====================================================
# Trusted Hosts
# =====================================================
allowed_hosts = getattr(settings, "allowed_hosts", ["*"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

# =====================================================
# CORS
# =====================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# Rate Limiter
# =====================================================
app.add_middleware(SlowAPIMiddleware)

# =====================================================
# Security Middleware Stack
# =====================================================
app.middleware("http")(error_tracker_middleware)
app.middleware("http")(abuse_guard_middleware)
app.middleware("http")(intrusion_detection_middleware)
app.middleware("http")(firewall_middleware)
app.middleware("http")(observability_middleware)
app.middleware("http")(alerting_middleware)

# =====================================================
# Security Headers (FIXED CSP)
# =====================================================
@app.middleware("http")
async def security_headers(request: Request, call_next: Callable):
    response = await call_next(request)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )

        # ✅ FIX: allow frontend to connect to backend
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "style-src 'self'; "
            "font-src 'self'; "
            "connect-src 'self' https://samhm-backend.onrender.com;"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval';"
        )

    return response


# =====================================================
# Request Logging
# =====================================================
@app.middleware("http")
async def log_requests(request: Request, call_next: Callable):
    ip = request.client.host if request.client else "unknown"

    logger.info(
        "Request | method=%s path=%s ip=%s",
        request.method,
        request.url.path,
        ip,
    )

    response = await call_next(request)

    logger.info(
        "Response | path=%s status=%s",
        request.url.path,
        response.status_code,
    )

    return response


# =====================================================
# Exception Handlers
# =====================================================
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please slow down."},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# =====================================================
# Health Model
# =====================================================
class HealthResponse(BaseModel):
    message: str
    version: str
    status: str


# =====================================================
# Root
# =====================================================
@app.get("/", include_in_schema=False)
async def root():
    if settings.is_production:
        return {"message": "SAMHM API running"}
    return RedirectResponse("/docs")


# =====================================================
# Health Endpoints
# =====================================================
@app.get(f"{API_PREFIX}/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    return HealthResponse(
        message="SAMHM Backend API is running",
        version=settings.APP_VERSION,
        status="OK",
    )


@app.get(
    f"{API_PREFIX}/health/details",
    response_model=HealthResponse,
    tags=["Health"],
)
async def detailed_health_check():
    return HealthResponse(
        message="All systems operational",
        version=settings.APP_VERSION,
        status="OK",
    )


# =====================================================
# Routers
# =====================================================
app.include_router(auth.router, prefix=f"{API_PREFIX}/auth", tags=["Auth"])
app.include_router(admin.router, prefix=f"{API_PREFIX}/admin", tags=["Admin"])
app.include_router(users.router, prefix=API_PREFIX)
app.include_router(sentiment.router, prefix=f"{API_PREFIX}/sentiment", tags=["Sentiment"])
app.include_router(privacy.router, prefix=f"{API_PREFIX}/privacy", tags=["Privacy"])
app.include_router(security_dashboard.router, prefix=f"{API_PREFIX}/security", tags=["Security"])
app.include_router(dashboard.router, prefix=f"{API_PREFIX}/dashboard", tags=["Dashboard"])
app.include_router(history.router, prefix=f"{API_PREFIX}/history", tags=["History"])
app.include_router(reports.router, prefix=f"{API_PREFIX}/reports", tags=["Reports"])
app.include_router(monitoring_router, prefix=f"{API_PREFIX}/monitoring", tags=["Monitoring"])
app.include_router(debug_router, prefix=f"{API_PREFIX}/debug", tags=["Debug"])


# =====================================================
# Lifecycle
# =====================================================
@app.on_event("startup")
async def startup_event():
    if settings.DB_AUTO_CREATE:
        try:
            initialize_database()
            logger.info("Database initialized successfully")
        except Exception:
            logger.exception("Database initialization failed")

    SentimentService.warm_up()

    logger.info(
        "SAMHM API started | env=%s version=%s",
        settings.APP_ENV,
        settings.APP_VERSION,
    )


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("SAMHM API shutting down")
