from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timedelta
from io import StringIO
import re
import textwrap

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import (
    AnalysisRequest,
    AnalysisResult,
    AuditLog,
    ReportJob,
    ReportStatus,
    User,
)
from app.services.dashboard_service import build_dashboard_summary

SUPPORTED_REPORT_FORMATS = {"csv", "pdf"}

HIGH_RISK_EMOTIONS = {
    "suicidal",
    "suicide",
    "self harm",
    "self-harm",
}

RAW_CSV_COLUMNS = [
    "timestamp",
    "analysis_id",
    "user_id",
    "input_type",
    "source_platform",
    "source_reference",
    "message_or_text_length",
    "word_count",
    "predicted_emotion",
    "sentiment",
    "confidence_score",
    "risk_flag",
    "system_status",
    "model_name",
    "model_version",
    "processing_seconds",
    "completed_at",
]


def _apply_user_scope_to_analysis_query(base_query, user_scope: str):
    if user_scope == "admins_only":
        return base_query.join(User, User.id == AnalysisRequest.user_id).where(
            User.role.has(name="admin")
        )
    if user_scope == "non_admins_only":
        return base_query.join(User, User.id == AnalysisRequest.user_id).where(
            ~User.role.has(name="admin")
        )
    return base_query


def _apply_user_scope_to_request_query(base_query, user_scope: str):
    if user_scope == "admins_only":
        return base_query.join(User, User.id == AnalysisRequest.user_id).where(
            User.role.has(name="admin")
        )
    if user_scope == "non_admins_only":
        return base_query.join(User, User.id == AnalysisRequest.user_id).where(
            ~User.role.has(name="admin")
        )
    return base_query


def _apply_user_scope_to_audit_query(base_query, user_scope: str):
    if user_scope == "admins_only":
        return base_query.join(User, User.id == AuditLog.user_id).where(
            User.role.has(name="admin")
        )
    if user_scope == "non_admins_only":
        return base_query.join(User, User.id == AuditLog.user_id).where(
            ~User.role.has(name="admin")
        )
    return base_query


def _build_csv_content(metrics: list[dict]) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["key", "label", "value"])
    for metric in metrics:
        writer.writerow([metric["key"], metric["label"], metric["value"]])
    return buffer.getvalue().strip()


def _build_raw_csv_content(rows: list[dict]) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(RAW_CSV_COLUMNS)

    for row in rows:
        writer.writerow([row.get(column, "") for column in RAW_CSV_COLUMNS])

    return buffer.getvalue().strip()


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "report"


def _report_download_basename(report_type: str, generated_at: datetime) -> str:
    timestamp = generated_at.strftime("%Y%m%d-%H%M%S")
    return f"{_safe_filename(report_type)}-{timestamp}"


def _scope_label(user_scope: str) -> str:
    return {
        "all_users": "All users",
        "admins_only": "Admins only",
        "non_admins_only": "Non-admins only",
    }.get(user_scope, user_scope.replace("_", " ").title())


def _pdf_escape(value: str) -> str:
    normalized = (
        value.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )
    return normalized.encode("ascii", "replace").decode("ascii")


def _wrap_pdf_line(value: str, *, width: int = 88) -> list[str]:
    clean = value.strip()
    if not clean:
        return [""]
    return textwrap.wrap(
        clean, width=width, break_long_words=True, break_on_hyphens=False
    ) or [clean]


def _render_pdf_document(title: str, lines: list[str]) -> bytes:
    wrapped_lines = [title, ""] + [
        segment for line in lines for segment in _wrap_pdf_line(line)
    ]
    body_lines_per_page = 42
    pages = [
        wrapped_lines[index : index + body_lines_per_page]
        for index in range(0, len(wrapped_lines), body_lines_per_page)
    ] or [[title]]

    font_object_id = 3 + (len(pages) * 2)
    objects: list[bytes] = []
    page_object_ids: list[int] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")

    for page_index, page_lines in enumerate(pages):
        page_object_id = 3 + (page_index * 2)
        content_object_id = page_object_id + 1
        page_object_ids.append(page_object_id)

        commands = ["BT", "/F1 20 Tf", "50 760 Td"]
        for line_index, line in enumerate(page_lines):
            if line_index == 1:
                commands.append("0 -26 Td")
                commands.append("/F1 11 Tf")
            elif line_index > 1:
                commands.append("0 -16 Td")
            commands.append(f"({_pdf_escape(line)}) Tj")
        commands.append("ET")
        stream_bytes = "\n".join(commands).encode("ascii")

        page_object = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_object_id} 0 R >> >> "
            f"/Contents {content_object_id} 0 R >>"
        ).encode("ascii")
        content_object = (
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )

        objects.append(page_object)
        objects.append(content_object)

    kids = " ".join(f"{object_id} 0 R" for object_id in page_object_ids)
    objects[1] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_ids)} >>".encode(
            "ascii"
        )
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("ascii")
    )
    return bytes(output)


def _fetch_completed_analysis_rows(
    db: Session,
    *,
    window_start: datetime,
    user_scope: str,
):
    query = (
        select(AnalysisRequest, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.analysis_request_id == AnalysisRequest.id)
        .where(
            AnalysisRequest.status == "completed",
            AnalysisRequest.submitted_at >= window_start,
        )
    )
    return db.execute(_apply_user_scope_to_analysis_query(query, user_scope)).all()


def _fetch_window_requests(
    db: Session,
    *,
    window_start: datetime,
    user_scope: str,
):
    query = select(AnalysisRequest).where(AnalysisRequest.submitted_at >= window_start)
    return (
        db.execute(_apply_user_scope_to_request_query(query, user_scope))
        .scalars()
        .all()
    )


def _fetch_audit_failures(
    db: Session,
    *,
    window_start: datetime,
    user_scope: str,
):
    query = select(AuditLog).where(
        AuditLog.occurred_at >= window_start,
        AuditLog.outcome != "success",
    )
    return (
        db.execute(_apply_user_scope_to_audit_query(query, user_scope)).scalars().all()
    )


def _count_users_for_scope(db: Session, *, user_scope: str) -> int:
    query = select(func.count(User.id))
    if user_scope == "admins_only":
        query = query.where(User.role.has(name="admin"))
    elif user_scope == "non_admins_only":
        query = query.where(~User.role.has(name="admin"))
    return db.execute(query).scalar_one()


def _format_counter(counter: Counter, *, limit: int = 4) -> str:
    if not counter:
        return "none"

    total = sum(counter.values()) or 1
    return " | ".join(
        f"{label}: {count} ({(count / total) * 100:.1f}%)"
        for label, count in counter.most_common(limit)
    )


def _counter_chart_lines(title: str, counter: Counter, *, limit: int = 6) -> list[str]:
    if not counter:
        return [f"{title}: no data"]

    max_count = max(counter.values())
    lines = [title]
    for label, count in counter.most_common(limit):
        bar_size = int((count / max_count) * 24) if max_count else 0
        bar = "#" * max(1, bar_size)
        lines.append(f"  {label:<14} {bar} ({count})")
    return lines


def _build_raw_export_rows(
    db: Session,
    *,
    window_start: datetime,
    user_scope: str,
) -> list[dict]:
    query = (
        select(AnalysisRequest, AnalysisResult)
        .outerjoin(
            AnalysisResult, AnalysisResult.analysis_request_id == AnalysisRequest.id
        )
        .where(AnalysisRequest.submitted_at >= window_start)
        .order_by(AnalysisRequest.submitted_at.desc())
    )
    rows = db.execute(_apply_user_scope_to_analysis_query(query, user_scope)).all()

    output: list[dict] = []
    for request, result in rows:
        emotion = (result.emotion_label if result else "") or ""
        sentiment = (result.sentiment_label if result else "") or ""
        confidence = result.confidence_score if result else None
        source_reference = request.source_reference or ""
        processing_seconds = (
            (request.completed_at - request.submitted_at).total_seconds()
            if request.completed_at and request.submitted_at
            else None
        )
        normalized_emotion = emotion.strip().lower().replace("_", " ").replace("-", " ")
        risk_flag = normalized_emotion in HIGH_RISK_EMOTIONS

        output.append(
            {
                "timestamp": request.submitted_at.isoformat(),
                "analysis_id": request.id,
                "user_id": request.user_id,
                "input_type": request.input_type or "",
                "source_platform": request.source_platform or "",
                "source_reference": source_reference,
                "message_or_text_length": request.text_length
                or request.word_count
                or 0,
                "word_count": request.word_count or 0,
                "predicted_emotion": emotion,
                "sentiment": sentiment,
                "confidence_score": (
                    f"{confidence:.4f}" if confidence is not None else ""
                ),
                "risk_flag": "true" if risk_flag else "false",
                "system_status": request.status or "unknown",
                "model_name": request.model_name or "",
                "model_version": request.model_version or "",
                "processing_seconds": (
                    f"{processing_seconds:.3f}"
                    if processing_seconds is not None
                    else ""
                ),
                "completed_at": (
                    request.completed_at.isoformat() if request.completed_at else ""
                ),
            }
        )

    return output


def _build_pdf_lines(preview: dict, raw_rows: list[dict]) -> list[str]:
    lines = [
        f"Report type: {preview['report_type']}",
        f"Date range: Last {preview['date_range_days']} days",
        f"User scope: {_scope_label(preview['user_scope'])}",
        f"Generated at: {preview['generated_at'].strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "Executive summary metrics:",
        *[f"- {metric['label']}: {metric['value']}" for metric in preview["metrics"]],
        "",
    ]

    completed_rows = [row for row in raw_rows if row["system_status"] == "completed"]
    emotion_counter = Counter(
        row["predicted_emotion"] for row in completed_rows if row["predicted_emotion"]
    )
    sentiment_counter = Counter(
        row["sentiment"] for row in completed_rows if row["sentiment"]
    )
    input_counter = Counter(row["input_type"] for row in raw_rows if row["input_type"])
    source_counter = Counter(
        row["source_platform"] for row in raw_rows if row["source_platform"]
    )
    status_counter = Counter(
        row["system_status"] for row in raw_rows if row["system_status"]
    )
    user_counter = Counter(row["user_id"] for row in raw_rows if row["user_id"])
    daily_counter = Counter(
        row["timestamp"][:10] for row in raw_rows if row["timestamp"]
    )
    risk_daily_counter = Counter(
        row["timestamp"][:10]
        for row in raw_rows
        if row["timestamp"] and row.get("risk_flag") == "true"
    )

    lines.extend(
        _counter_chart_lines("Emotion distribution (text chart)", emotion_counter)
    )
    lines.append("")
    lines.extend(
        _counter_chart_lines("Sentiment distribution (text chart)", sentiment_counter)
    )
    lines.append("")
    lines.extend(_counter_chart_lines("Input type distribution", input_counter))
    lines.append("")
    lines.extend(_counter_chart_lines("Source platform distribution", source_counter))
    lines.append("")
    lines.extend(_counter_chart_lines("System status distribution", status_counter))
    lines.append("")
    lines.extend(_counter_chart_lines("Analyses over time", daily_counter))
    lines.append("")
    lines.extend(
        _counter_chart_lines("High-risk trend (suicidal-related)", risk_daily_counter)
    )

    lines.append("")
    lines.append("Top users by analyses:")
    if user_counter:
        for user_id, count in user_counter.most_common(8):
            lines.append(f"  {user_id[:12]}... : {count}")
    else:
        lines.append("  no user activity in selected window")

    lines.append("")
    lines.append("Recent records sample:")
    for row in raw_rows[:12]:
        lines.append(
            "  "
            f"{row['timestamp'][:19]} | {row['input_type'] or 'n/a'} | "
            f"{row['predicted_emotion'] or row['sentiment'] or 'n/a'} | "
            f"conf {row['confidence_score'] or '-'} | risk {row['risk_flag']} | "
            f"status {row['system_status']}"
        )

    lines.append("")
    lines.append("Raw export CSV columns:")
    lines.append(", ".join(RAW_CSV_COLUMNS))
    return lines


def build_report_export(
    db: Session,
    *,
    report_type: str,
    date_range_days: int,
    user_scope: str,
    report_format: str,
) -> tuple[str, bytes, str, dict]:
    preview = build_report_preview(
        db,
        report_type=report_type,
        date_range_days=date_range_days,
        user_scope=user_scope,
    )
    basename = preview["download_basename"]
    window_start = preview["generated_at"] - timedelta(days=date_range_days)
    raw_rows = _build_raw_export_rows(
        db, window_start=window_start, user_scope=user_scope
    )

    if report_format == "csv":
        return (
            f"{basename}.csv",
            _build_raw_csv_content(raw_rows).encode("utf-8"),
            "text/csv; charset=utf-8",
            preview,
        )
    if report_format == "pdf":
        return (
            f"{basename}.pdf",
            _render_pdf_document(
                preview["report_type"], _build_pdf_lines(preview, raw_rows)
            ),
            "application/pdf",
            preview,
        )

    raise ValueError(f"Unsupported report format: {report_format}")


def build_dashboard_export(
    db: Session,
    *,
    days: int,
    report_format: str,
) -> tuple[str, bytes, str]:
    generated_at = datetime.utcnow()
    summary = build_dashboard_summary(db, days=days)

    metrics = [
        {
            "key": "total_analyses",
            "label": "Total Analyses",
            "value": str(summary["total_analyses"]),
        },
        {
            "key": "average_confidence",
            "label": "Average Confidence",
            "value": f"{summary['average_confidence'] * 100:.1f}%",
        },
        {
            "key": "distinct_users",
            "label": "Distinct Users",
            "value": str(summary["distinct_users"]),
        },
        {
            "key": "top_sentiment",
            "label": "Top Sentiment",
            "value": (
                summary["sentiment_distribution"][0]["label"]
                if summary["sentiment_distribution"]
                else "none"
            ),
        },
        {
            "key": "top_emotion",
            "label": "Top Emotion",
            "value": (
                summary["emotion_distribution"][0]["label"]
                if summary["emotion_distribution"]
                else "none"
            ),
        },
        {
            "key": "top_input_type",
            "label": "Top Input Type",
            "value": (
                summary["input_type_distribution"][0]["label"]
                if summary["input_type_distribution"]
                else "none"
            ),
        },
    ]
    basename = _report_download_basename("admin-dashboard", generated_at)

    if report_format == "csv":
        csv_lines = _build_csv_content(metrics)
        return f"{basename}.csv", csv_lines.encode("utf-8"), "text/csv; charset=utf-8"

    if report_format == "pdf":
        lines = [
            f"Dashboard window: Last {days} days",
            f"Generated at: {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            *[f"{metric['label']}: {metric['value']}" for metric in metrics],
            "",
            "Daily trends:",
            *[
                f"{item['date']}: {item['analyses']} analyses, avg confidence {item['average_confidence'] * 100:.1f}%"
                for item in summary["daily_trends"][-10:]
            ],
            "",
            "Recent analyses:",
            *[
                f"{item['submitted_at']}: {item['emotion'] or item['sentiment']} via {item['input_type']} at {item['confidence'] * 100:.1f}%"
                for item in summary["recent_analyses"][:8]
            ],
        ]
        return (
            f"{basename}.pdf",
            _render_pdf_document("Admin Dashboard Snapshot", lines),
            "application/pdf",
        )

    raise ValueError(f"Unsupported report format: {report_format}")


def build_report_preview(
    db: Session,
    *,
    report_type: str,
    date_range_days: int,
    user_scope: str,
) -> dict:
    generated_at = datetime.utcnow()
    window_start = generated_at - timedelta(days=date_range_days)

    completed_rows = _fetch_completed_analysis_rows(
        db,
        window_start=window_start,
        user_scope=user_scope,
    )
    request_rows = _fetch_window_requests(
        db,
        window_start=window_start,
        user_scope=user_scope,
    )
    audit_failures = _fetch_audit_failures(
        db,
        window_start=window_start,
        user_scope=user_scope,
    )

    sentiment_counter = Counter(
        result.sentiment_label for _, result in completed_rows if result.sentiment_label
    )
    emotion_counter = Counter(
        result.emotion_label for _, result in completed_rows if result.emotion_label
    )
    input_counter = Counter(
        request.input_type for request in request_rows if request.input_type
    )
    platform_counter = Counter(
        request.source_platform for request in request_rows if request.source_platform
    )
    user_activity_counter = Counter(
        request.user_id for request in request_rows if request.user_id
    )
    daily_counter = Counter(
        request.submitted_at.strftime("%Y-%m-%d")
        for request in request_rows
        if request.submitted_at
    )
    model_counter = Counter(
        request.model_name for request, _ in completed_rows if request.model_name
    )

    completed_count = len(completed_rows)
    window_count = len(request_rows)
    active_users = len({request.user_id for request in request_rows})
    chat_interactions = input_counter.get("text", 0)
    failed_analyses = sum(
        1 for request in request_rows if request.status != "completed"
    )
    average_confidence = (
        sum(result.confidence_score for _, result in completed_rows) / completed_count
        if completed_count
        else 0.0
    )
    top_emotion = emotion_counter.most_common(1)[0][0] if emotion_counter else "none"
    top_sentiment = (
        sentiment_counter.most_common(1)[0][0] if sentiment_counter else "none"
    )
    high_risk_cases = sum(
        1
        for _, result in completed_rows
        if (result.emotion_label or "")
        .strip()
        .lower()
        .replace("_", " ")
        .replace("-", " ")
        in HIGH_RISK_EMOTIONS
    )

    if report_type == "User Activity":
        metrics = [
            {
                "key": "total_users",
                "label": "Total Users",
                "value": str(_count_users_for_scope(db, user_scope=user_scope)),
            },
            {
                "key": "active_users",
                "label": "Active Users",
                "value": str(active_users),
            },
            {
                "key": "analyses",
                "label": "Analyses in Window",
                "value": str(window_count),
            },
            {
                "key": "chat_interactions",
                "label": "Chat Interactions (text input)",
                "value": str(chat_interactions),
            },
            {
                "key": "analyses_per_user",
                "label": "Analyses per User",
                "value": _format_counter(user_activity_counter, limit=5),
            },
            {
                "key": "window",
                "label": "Date Range",
                "value": f"{date_range_days} days",
            },
        ]
    elif report_type == "System Performance":
        trend_text = (
            " | ".join(
                f"{day}:{count}" for day, count in sorted(daily_counter.items())[-7:]
            )
            or "none"
        )
        metrics = [
            {
                "key": "processed_requests",
                "label": "Predictions Processed",
                "value": str(completed_count),
            },
            {
                "key": "avg_confidence",
                "label": "Average Confidence",
                "value": f"{average_confidence * 100:.1f}%",
            },
            {
                "key": "top_model",
                "label": "Top Model",
                "value": (
                    model_counter.most_common(1)[0][0] if model_counter else "unknown"
                ),
            },
            {
                "key": "processing_trend",
                "label": "Processing Trend (last 7 points)",
                "value": trend_text,
            },
            {
                "key": "high_risk",
                "label": "High-Risk Cases",
                "value": str(high_risk_cases),
            },
            {
                "key": "window",
                "label": "Date Range",
                "value": f"{date_range_days} days",
            },
        ]
    elif report_type == "Error Logs":
        action_counter = Counter(
            log.action_type for log in audit_failures if log.action_type
        )
        metrics = [
            {
                "key": "failed_analyses",
                "label": "Failed Analyses",
                "value": str(failed_analyses),
            },
            {
                "key": "failure_rate",
                "label": "Failure Rate",
                "value": f"{((failed_analyses / window_count) * 100 if window_count else 0):.1f}%",
            },
            {
                "key": "audit_failures",
                "label": "System Error Events",
                "value": str(len(audit_failures)),
            },
            {
                "key": "top_error_action",
                "label": "Top Error Action",
                "value": (
                    action_counter.most_common(1)[0][0] if action_counter else "none"
                ),
            },
            {
                "key": "window",
                "label": "Date Range",
                "value": f"{date_range_days} days",
            },
        ]
    else:
        metrics = [
            {
                "key": "total_analyses",
                "label": "Total Analyses",
                "value": str(completed_count),
            },
            {
                "key": "active_users",
                "label": "Active Users",
                "value": str(active_users),
            },
            {
                "key": "avg_confidence",
                "label": "Average Confidence",
                "value": f"{average_confidence * 100:.1f}%",
            },
            {
                "key": "dominant_emotion",
                "label": "Dominant Emotion",
                "value": top_emotion,
            },
            {"key": "top_sentiment", "label": "Top Sentiment", "value": top_sentiment},
            {
                "key": "sentiment_distribution",
                "label": "Sentiment Distribution",
                "value": _format_counter(sentiment_counter),
            },
            {
                "key": "emotion_distribution",
                "label": "Emotion Distribution",
                "value": _format_counter(emotion_counter),
            },
            {
                "key": "input_types",
                "label": "Input Type Mix",
                "value": _format_counter(input_counter),
            },
            {
                "key": "platform_mix",
                "label": "Source Platform Mix",
                "value": _format_counter(platform_counter),
            },
            {
                "key": "high_risk",
                "label": "High-Risk Cases",
                "value": str(high_risk_cases),
            },
        ]

    download_basename = _report_download_basename(report_type, generated_at)
    return {
        "report_type": report_type,
        "date_range_days": date_range_days,
        "user_scope": user_scope,
        "generated_at": generated_at,
        "metrics": metrics,
        "csv_content": _build_csv_content(metrics),
        "download_basename": download_basename,
    }


def create_report_job(
    db: Session,
    *,
    user_id: str,
    report_type: str,
    date_range_days: int,
    user_scope: str,
    report_format: str,
) -> tuple[ReportJob, dict]:
    preview = build_report_preview(
        db,
        report_type=report_type,
        date_range_days=date_range_days,
        user_scope=user_scope,
    )

    report_job = ReportJob(
        requested_by_id=user_id,
        report_name=report_type,
        report_format=report_format,
        status=ReportStatus.COMPLETED.value,
        filter_payload={
            "date_range_days": date_range_days,
            "user_scope": user_scope,
            "metrics": preview["metrics"],
        },
        generated_at=preview["generated_at"],
        expires_at=preview["generated_at"] + timedelta(days=7),
        storage_path=f"generated://reports/{report_type.lower().replace(' ', '-')}.{report_format}",
    )
    db.add(report_job)
    db.flush()

    return report_job, preview
