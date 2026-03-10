from app.monitoring.engine import metrics_engine


async def observability_middleware(request, call_next):

    metrics_engine.inc("requests_total")
    metrics_engine.track_endpoint(request.url.path)

    if request.client:
        metrics_engine.track_ip(request.client.host)

    response = await call_next(request)

    metrics_engine.inc(f"status_{response.status_code}")

    return response
