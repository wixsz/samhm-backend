import traceback
import logging
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("SAMHM.Errors")


async def error_tracker_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:
        logger.error("Unhandled exception\n%s", traceback.format_exc())

        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )
