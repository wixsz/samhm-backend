import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditLog, ReportJob
from app.db.session import get_db
from app.schemas.report import (
    ReportGenerateRequest,
    ReportJobItem,
    ReportJobListResponse,
    ReportPreview,
)
from app.security.rbac import require_permission
from app.services.report_service import (
    SUPPORTED_REPORT_FORMATS,
    build_dashboard_export,
    build_report_export,
    build_report_preview,
    create_report_job,
)

logger = logging.getLogger("SAMHM.Reports")

router = APIRouter()


def _normalize_download_args(report_format: str, disposition: str) -> tuple[str, str]:
    normalized_format = report_format.lower()
    normalized_disposition = disposition.lower()

    if normalized_format not in SUPPORTED_REPORT_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported report format '{report_format}'. Use csv or pdf.",
        )
    if normalized_disposition not in {"attachment", "inline"}:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported disposition '{disposition}'. Use attachment or inline.",
        )

    return normalized_format, normalized_disposition


@router.get(
    "/preview",
    response_model=ReportPreview,
    summary="Preview a report without saving",
)
def preview_report(
    report_type: str = Query("Analysis Summary"),
    date_range_days: int = Query(30, ge=1, le=365),
    user_scope: str = Query("all_users"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    preview = build_report_preview(
        db,
        report_type=report_type,
        date_range_days=date_range_days,
        user_scope=user_scope,
    )
    logger.info(
        "Report preview requested | user=%s type=%s days=%s scope=%s",
        current_user["email"],
        report_type,
        date_range_days,
        user_scope,
    )
    return preview


@router.post(
    "/generate",
    response_model=ReportPreview,
    summary="Generate and persist a report job",
)
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    report_job, preview = create_report_job(
        db,
        user_id=current_user["id"],
        report_type=payload.report_type,
        date_range_days=payload.date_range_days,
        user_scope=payload.user_scope,
        report_format=payload.report_format,
    )

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="generate_report",
            entity_type="report_job",
            entity_id=report_job.id,
            outcome="success",
            details={
                "report_type": payload.report_type,
                "date_range_days": payload.date_range_days,
                "user_scope": payload.user_scope,
                "report_format": payload.report_format,
            },
        )
    )
    db.commit()

    logger.info(
        "Report generated | user=%s report_id=%s type=%s",
        current_user["email"],
        report_job.id,
        payload.report_type,
    )
    return preview


@router.get(
    "/download",
    summary="Download a report export as CSV or PDF",
)
def download_report(
    report_type: str = Query("Analysis Summary"),
    date_range_days: int = Query(30, ge=1, le=365),
    user_scope: str = Query("all_users"),
    report_format: str = Query("csv"),
    disposition: str = Query("attachment"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    normalized_format, normalized_disposition = _normalize_download_args(
        report_format,
        disposition,
    )
    filename, content, media_type, preview = build_report_export(
        db,
        report_type=report_type,
        date_range_days=date_range_days,
        user_scope=user_scope,
        report_format=normalized_format,
    )

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="download_report",
            entity_type="report_export",
            entity_id=preview["download_basename"],
            outcome="success",
            details={
                "report_type": report_type,
                "date_range_days": date_range_days,
                "user_scope": user_scope,
                "report_format": normalized_format,
                "disposition": normalized_disposition,
            },
        )
    )
    db.commit()

    logger.info(
        "Report download requested | user=%s type=%s format=%s",
        current_user["email"],
        report_type,
        normalized_format,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{normalized_disposition}; filename="{filename}"',
        },
    )


@router.get(
    "/dashboard-download",
    summary="Download the admin dashboard summary as CSV or PDF",
)
def download_dashboard(
    days: int = Query(30, ge=1, le=365),
    report_format: str = Query("pdf"),
    disposition: str = Query("attachment"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    normalized_format, normalized_disposition = _normalize_download_args(
        report_format,
        disposition,
    )
    filename, content, media_type = build_dashboard_export(
        db,
        days=days,
        report_format=normalized_format,
    )

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="download_dashboard_report",
            entity_type="dashboard_export",
            entity_id=filename,
            outcome="success",
            details={
                "days": days,
                "report_format": normalized_format,
                "disposition": normalized_disposition,
            },
        )
    )
    db.commit()

    logger.info(
        "Dashboard export requested | user=%s days=%s format=%s",
        current_user["email"],
        days,
        normalized_format,
    )
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{normalized_disposition}; filename="{filename}"',
        },
    )


@router.get(
    "/jobs",
    response_model=ReportJobListResponse,
    summary="List generated report jobs",
)
def list_report_jobs(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_permission("view_metrics")),
):
    jobs = (
        db.execute(select(ReportJob).order_by(ReportJob.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )

    return ReportJobListResponse(
        items=[
            ReportJobItem(
                id=job.id,
                report_name=job.report_name,
                report_format=job.report_format,
                status=job.status,
                generated_at=job.generated_at,
                created_at=job.created_at,
                expires_at=job.expires_at,
                filter_payload=job.filter_payload,
            )
            for job in jobs
        ]
    )
