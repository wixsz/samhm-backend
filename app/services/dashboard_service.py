from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.db.models import AnalysisRequest, AnalysisResult, DashboardScope, KpiSnapshot


def _distribution(counter: Counter, total: int) -> list[dict]:
    if total == 0:
        return []

    return [
        {
            "label": label,
            "count": count,
            "percentage": round((count / total) * 100, 2),
        }
        for label, count in counter.most_common()
    ]


def _base_summary_query(window_start: datetime) -> Select:
    return (
        select(AnalysisRequest, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.analysis_request_id == AnalysisRequest.id)
        .where(
            AnalysisRequest.status == "completed",
            AnalysisRequest.submitted_at >= window_start,
        )
        .order_by(AnalysisRequest.submitted_at.desc())
    )


def build_dashboard_summary(
    db: Session,
    *,
    days: int = 30,
    user_id: str | None = None,
    recent_limit: int = 10,
) -> dict:
    window_start = datetime.utcnow() - timedelta(days=days)
    query = _base_summary_query(window_start)

    if user_id is not None:
        query = query.where(AnalysisRequest.user_id == user_id)

    rows = db.execute(query).all()

    sentiment_counter: Counter = Counter()
    emotion_counter: Counter = Counter()
    input_type_counter: Counter = Counter()
    trend_buckets: dict[str, list[float]] = defaultdict(list)
    recent_analyses: list[dict] = []
    distinct_users: set[str] = set()

    for index, (request, result) in enumerate(rows):
        distinct_users.add(request.user_id)
        sentiment_counter[result.sentiment_label] += 1
        if result.emotion_label:
            emotion_counter[result.emotion_label] += 1
        input_type_counter[request.input_type] += 1

        bucket = request.submitted_at.strftime("%Y-%m-%d")
        trend_buckets[bucket].append(result.confidence_score)

        if index < recent_limit:
            recent_analyses.append(
                {
                    "analysis_id": request.id,
                    "input_type": request.input_type,
                    "sentiment": result.sentiment_label,
                    "emotion": result.emotion_label,
                    "confidence": result.confidence_score,
                    "submitted_at": request.submitted_at,
                    "model_version": request.model_version,
                }
            )

    total_analyses = len(rows)
    avg_confidence = (
        round(
            sum(item["confidence"] for item in recent_analyses) / len(recent_analyses),
            4,
        )
        if recent_analyses
        else 0.0
    )

    if total_analyses > len(recent_analyses):
        avg_confidence = round(
            sum(result.confidence_score for _, result in rows) / total_analyses,
            4,
        )

    daily_trends = [
        {
            "date": date,
            "analyses": len(confidences),
            "average_confidence": round(sum(confidences) / len(confidences), 4),
        }
        for date, confidences in sorted(trend_buckets.items())
    ]

    return {
        "total_analyses": total_analyses,
        "average_confidence": avg_confidence,
        "distinct_users": len(distinct_users),
        "sentiment_distribution": _distribution(sentiment_counter, total_analyses),
        "emotion_distribution": _distribution(emotion_counter, total_analyses),
        "input_type_distribution": _distribution(input_type_counter, total_analyses),
        "daily_trends": daily_trends,
        "recent_analyses": recent_analyses,
    }


def refresh_daily_kpi_snapshots(db: Session, *, user_id: str | None = None) -> None:
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    tomorrow_start = today_start + timedelta(days=1)

    summary = build_dashboard_summary(db, days=1, user_id=user_id, recent_limit=10)
    scope_type = DashboardScope.USER.value if user_id else DashboardScope.GLOBAL.value
    scope_key = user_id or "all"

    metrics = [
        ("total_analyses", float(summary["total_analyses"]), None),
        ("average_confidence", float(summary["average_confidence"]), None),
        (
            "sentiment_distribution",
            float(summary["total_analyses"]),
            summary["sentiment_distribution"],
        ),
        (
            "input_type_distribution",
            float(summary["total_analyses"]),
            summary["input_type_distribution"],
        ),
    ]

    for metric_name, metric_value, breakdown in metrics:
        existing = db.execute(
            select(KpiSnapshot).where(
                KpiSnapshot.scope_type == scope_type,
                KpiSnapshot.scope_key == scope_key,
                KpiSnapshot.metric_name == metric_name,
                KpiSnapshot.window_start == today_start,
                KpiSnapshot.window_end == tomorrow_start,
            )
        ).scalar_one_or_none()

        if existing is None:
            existing = KpiSnapshot(
                scope_type=scope_type,
                scope_key=scope_key,
                metric_name=metric_name,
                metric_value=metric_value,
                window_start=today_start,
                window_end=tomorrow_start,
            )
            db.add(existing)

        existing.metric_value = metric_value
        existing.breakdown = breakdown
        existing.snapshot_metadata = {"generated_at": datetime.utcnow().isoformat()}
