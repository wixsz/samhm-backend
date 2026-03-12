from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.db.models import (
    AnalysisRequest,
    AnalysisResult,
    AuditLog,
    ConsentRecord,
    ReportJob,
    Role,
    User,
)
from app.monitoring.health import system_health
from app.security.security_events import get_all_events, get_suspicious_ips
from app.services.sentiment_service import SentimentService


def _format_details(details: dict | None) -> str:
    if not details:
        return "No additional details"

    parts = []
    for key, value in details.items():
        if value in (None, "", [], {}):
            continue
        label = key.replace("_", " ")
        parts.append(f"{label}: {value}")

    return " | ".join(parts) if parts else "No additional details"


def build_admin_console_response(
    db: Session,
    *,
    current_user_id: str,
    log_limit: int = 50,
    user_limit: int = 100,
) -> dict:
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    total_users = db.scalar(select(func.count()).select_from(User)) or 0
    active_users = (
        db.scalar(
            select(func.count()).select_from(User).where(User.is_active.is_(True))
        )
        or 0
    )
    inactive_users = total_users - active_users

    role_distribution_rows = db.execute(
        select(Role.name, func.count(User.id))
        .select_from(Role)
        .outerjoin(User, User.role_id == Role.id)
        .group_by(Role.name)
        .order_by(Role.name.asc())
    ).all()
    role_distribution = [
        {"label": role_name, "count": count}
        for role_name, count in role_distribution_rows
    ]

    users = (
        db.execute(
            select(User)
            .options(joinedload(User.role))
            .order_by(User.created_at.desc())
            .limit(user_limit)
        )
        .scalars()
        .all()
    )
    user_items = [
        {
            "id": user.id,
            "full_name": user.full_name or user.email.split("@")[0],
            "email": user.email,
            "role": user.role.name if user.role else "user",
            "status": "active" if user.is_active else "inactive",
            "last_login_at": user.last_login_at,
            "created_at": user.created_at,
        }
        for user in users
    ]

    log_rows = db.execute(
        select(AuditLog, User, Role.name)
        .select_from(AuditLog)
        .outerjoin(User, AuditLog.user_id == User.id)
        .outerjoin(Role, User.role_id == Role.id)
        .order_by(AuditLog.occurred_at.desc())
        .limit(log_limit)
    ).all()
    log_items = [
        {
            "id": log.id,
            "occurred_at": log.occurred_at,
            "user_email": user.email if user else "system",
            "role": role_name or "system",
            "action_type": log.action_type,
            "entity_type": log.entity_type,
            "outcome": log.outcome,
            "details": _format_details(log.details),
        }
        for log, user, role_name in log_rows
    ]

    total_audit_logs = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    failures_last_24h = (
        db.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.occurred_at >= last_24h, AuditLog.outcome != "success")
        )
        or 0
    )
    uploads_last_24h = (
        db.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.occurred_at >= last_24h, AuditLog.action_type.like("%upload%")
            )
        )
        or 0
    )
    analyses_last_24h = (
        db.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.occurred_at >= last_24h, AuditLog.action_type.like("%analyze%")
            )
        )
        or 0
    )

    security_events = get_all_events()
    suspicious_ips = get_suspicious_ips()

    total_analyses = (
        db.scalar(
            select(func.count())
            .select_from(AnalysisRequest)
            .where(AnalysisRequest.status == "completed")
        )
        or 0
    )
    analyses_last_7_days = (
        db.scalar(
            select(func.count())
            .select_from(AnalysisRequest)
            .where(
                AnalysisRequest.status == "completed",
                AnalysisRequest.submitted_at >= last_7d,
            )
        )
        or 0
    )
    average_confidence = (
        db.scalar(
            select(
                func.coalesce(func.avg(AnalysisResult.confidence_score), 0.0)
            ).select_from(AnalysisResult)
        )
        or 0.0
    )
    # Input mix: text/link are counted per request, but batch is counted per uploaded file (batch_id).
    completed_input_rows = db.execute(
        select(
            AnalysisRequest.id,
            AnalysisRequest.input_type,
            AnalysisRequest.request_metadata,
        ).where(AnalysisRequest.status == "completed")
    ).all()

    input_counts: dict[str, int] = {}
    seen_batch_keys: set[str] = set()

    for analysis_id, input_type, request_metadata in completed_input_rows:
        normalized_type = (input_type or "").strip().lower()
        if not normalized_type:
            continue

        if normalized_type != "batch":
            input_counts[normalized_type] = input_counts.get(normalized_type, 0) + 1
            continue

        metadata = request_metadata if isinstance(request_metadata, dict) else {}
        batch_id = metadata.get("batch_id")
        if isinstance(batch_id, str) and batch_id.strip():
            batch_key = f"batch:{batch_id.strip()}"
        else:
            # Legacy fallback: if batch_id does not exist, keep per-request counting behavior.
            batch_key = f"analysis:{analysis_id}"

        if batch_key in seen_batch_keys:
            continue
        seen_batch_keys.add(batch_key)
        input_counts["batch"] = input_counts.get("batch", 0) + 1

    input_distribution = [
        {"label": label, "count": count}
        for label, count in sorted(input_counts.items(), key=lambda item: item[0])
    ]
    report_jobs_completed = (
        db.scalar(
            select(func.count())
            .select_from(ReportJob)
            .where(ReportJob.status == "completed")
        )
        or 0
    )

    consent_rows = db.execute(
        select(
            ConsentRecord.scope,
            func.sum(case((ConsentRecord.granted.is_(True), 1), else_=0)),
            func.sum(case((ConsentRecord.revoked_at.is_not(None), 1), else_=0)),
        )
        .group_by(ConsentRecord.scope)
        .order_by(ConsentRecord.scope.asc())
    ).all()
    consent_by_scope = [
        {
            "scope": scope,
            "granted_count": granted_count or 0,
            "revoked_count": revoked_count or 0,
        }
        for scope, granted_count, revoked_count in consent_rows
    ]
    total_consent_records = (
        db.scalar(select(func.count()).select_from(ConsentRecord)) or 0
    )
    exports_generated = (
        db.scalar(
            select(func.count())
            .select_from(ReportJob)
            .where(ReportJob.status == "completed")
        )
        or 0
    )
    audit_events_last_24h = (
        db.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.occurred_at >= last_24h)
        )
        or 0
    )

    current_admin = db.execute(
        select(User).options(joinedload(User.role)).where(User.id == current_user_id)
    ).scalar_one()
    current_admin_logs = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == current_user_id)
            .order_by(AuditLog.occurred_at.desc())
            .limit(8)
        )
        .scalars()
        .all()
    )
    recent_actions = [
        {
            "id": log.id,
            "occurred_at": log.occurred_at,
            "user_email": current_admin.email,
            "role": current_admin.role.name if current_admin.role else "admin",
            "action_type": log.action_type,
            "entity_type": log.entity_type,
            "outcome": log.outcome,
            "details": _format_details(log.details),
        }
        for log in current_admin_logs
    ]

    health = system_health()

    return {
        "users": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "role_distribution": role_distribution,
            "items": user_items,
        },
        "logs": {
            "total_audit_logs": total_audit_logs,
            "failures_last_24h": failures_last_24h,
            "uploads_last_24h": uploads_last_24h,
            "analyses_last_24h": analyses_last_24h,
            "security_event_count": len(security_events),
            "suspicious_ip_count": len(suspicious_ips),
            "items": log_items,
        },
        "models": {
            "current_model_version": SentimentService.get_model_version(),
            "total_analyses": total_analyses,
            "analyses_last_7_days": analyses_last_7_days,
            "average_confidence": float(average_confidence),
            "input_type_distribution": input_distribution,
            "report_jobs_completed": report_jobs_completed,
        },
        "privacy": {
            "total_consent_records": total_consent_records,
            "exports_generated": exports_generated,
            "audit_events_last_24h": audit_events_last_24h,
            "hashed_text_storage": bool(settings.TEXT_HASH_SALT),
            "consent_by_scope": consent_by_scope,
        },
        "settings": {
            "environment": settings.APP_ENV,
            "frontend_url": settings.FRONTEND_URL,
            "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            "rate_limit_per_minute": settings.RATE_LIMIT_PER_MINUTE,
            "db_auto_create": settings.DB_AUTO_CREATE,
            "health_status": health["status"],
            "cpu_percent": float(health["cpu_percent"]),
            "memory_percent": float(health["memory_percent"]),
        },
        "profile": {
            "email": current_admin.email,
            "full_name": current_admin.full_name or current_admin.email.split("@")[0],
            "role": current_admin.role.name if current_admin.role else "admin",
            "last_login_at": current_admin.last_login_at,
            "recent_actions": recent_actions,
        },
    }
