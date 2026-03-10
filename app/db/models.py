from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def generate_uuid() -> str:
    return str(uuid4())


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class RoleName(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    SECURITY = "security"
    USER = "user"


class ConsentScope(str, Enum):
    PRIVACY_POLICY = "privacy_policy"
    DATA_PROCESSING = "data_processing"
    RESEARCH_USE = "research_use"
    REPORT_EXPORT = "report_export"


class AnalysisInputType(str, Enum):
    TEXT = "text"
    LINK = "link"
    BATCH = "batch"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class DashboardScope(str, Enum):
    GLOBAL = "global"
    USER = "user"
    PLATFORM = "platform"
    MODEL = "model"
    INPUT_TYPE = "input_type"


class ReportFormat(str, Enum):
    CSV = "csv"
    PDF = "pdf"


class ReportStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Role(TimestampMixin, Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(255))

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    role: Mapped["Role"] = relationship(back_populates="users")
    consent_records: Mapped[list["ConsentRecord"]] = relationship(back_populates="user")
    analysis_requests: Mapped[list["AnalysisRequest"]] = relationship(back_populates="user")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")
    report_jobs: Mapped[list["ReportJob"]] = relationship(back_populates="requested_by")


class ConsentRecord(TimestampMixin, Base):
    __tablename__ = "consent_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    scope: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    granted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="consent_records")


class AnalysisRequest(TimestampMixin, Base):
    __tablename__ = "analysis_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    input_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source_platform: Mapped[str | None] = mapped_column(String(50))
    source_reference: Mapped[str | None] = mapped_column(String(1024))
    text_hash: Mapped[str | None] = mapped_column(String(255))
    text_length: Mapped[int | None] = mapped_column()
    word_count: Mapped[int | None] = mapped_column()
    status: Mapped[str] = mapped_column(String(20), default=AnalysisStatus.PENDING.value)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    model_name: Mapped[str | None] = mapped_column(String(100))
    model_version: Mapped[str | None] = mapped_column(String(100))
    request_metadata: Mapped[dict | None] = mapped_column(JSON)

    user: Mapped["User"] = relationship(back_populates="analysis_requests")
    results: Mapped[list["AnalysisResult"]] = relationship(back_populates="analysis_request")


class AnalysisResult(TimestampMixin, Base):
    __tablename__ = "analysis_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    analysis_request_id: Mapped[str] = mapped_column(
        ForeignKey("analysis_requests.id"),
        nullable=False,
    )
    sentiment_label: Mapped[str] = mapped_column(String(50), nullable=False)
    emotion_label: Mapped[str | None] = mapped_column(String(50))
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    explainability_summary: Mapped[dict | None] = mapped_column(JSON)
    result_metadata: Mapped[dict | None] = mapped_column(JSON)

    analysis_request: Mapped["AnalysisRequest"] = relationship(back_populates="results")


class KpiSnapshot(TimestampMixin, Base):
    __tablename__ = "kpi_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scope_type: Mapped[str] = mapped_column(String(50), nullable=False)
    scope_key: Mapped[str | None] = mapped_column(String(100))
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    metric_unit: Mapped[str | None] = mapped_column(String(25))
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    breakdown: Mapped[dict | None] = mapped_column(JSON)
    snapshot_metadata: Mapped[dict | None] = mapped_column(JSON)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(30), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict | None] = mapped_column(JSON)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        nullable=False,
    )

    user: Mapped[User | None] = relationship(back_populates="audit_logs")


class ReportJob(TimestampMixin, Base):
    __tablename__ = "report_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    requested_by_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    report_name: Mapped[str] = mapped_column(String(150), nullable=False)
    report_format: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ReportStatus.QUEUED.value)
    filter_payload: Mapped[dict | None] = mapped_column(JSON)
    storage_path: Mapped[str | None] = mapped_column(String(512))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    requested_by: Mapped["User"] = relationship(back_populates="report_jobs")


Index("ix_users_role_id", User.role_id)
Index("ix_consent_records_user_scope", ConsentRecord.user_id, ConsentRecord.scope)
Index("ix_analysis_requests_user_id", AnalysisRequest.user_id)
Index("ix_analysis_requests_submitted_at", AnalysisRequest.submitted_at)
Index("ix_analysis_requests_input_type", AnalysisRequest.input_type)
Index("ix_analysis_results_request_id", AnalysisResult.analysis_request_id)
Index(
    "ix_kpi_snapshots_scope_metric_window",
    KpiSnapshot.scope_type,
    KpiSnapshot.metric_name,
    KpiSnapshot.window_start,
)
Index("ix_audit_logs_occurred_at", AuditLog.occurred_at)
Index("ix_audit_logs_action_type", AuditLog.action_type)
Index("ix_report_jobs_requested_by_id", ReportJob.requested_by_id)
