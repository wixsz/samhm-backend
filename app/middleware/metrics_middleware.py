import time
from fastapi import Request
from app.monitoring.metrics import metrics


async def metrics_middleware(request: Request, call_next):
    start = time.time()

    metrics.record_request(request.url.path)

    try:
        response = await call_next(request)
    except Exception:
        metrics.record_error()
        raise

    duration = time.time() - start
    metrics.record_time(duration)

    if response.status_code >= 400:
        metrics.record_error()

    return response
