from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CountItem(BaseModel):
    label: str
    count: int = Field(..., ge=0)


class AdminUserItem(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    status: str
    last_login_at: datetime | None = None
    created_at: datetime


class AdminUserUpdateRequest(BaseModel):
    full_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)


class AdminUserActionResponse(BaseModel):
    id: str
    full_name: str
    email: str
    role: str
    status: str
    message: str


class AdminUsersSection(BaseModel):
    total_users: int = Field(..., ge=0)
    active_users: int = Field(..., ge=0)
    inactive_users: int = Field(..., ge=0)
    role_distribution: list[CountItem]
    items: list[AdminUserItem]


class AdminLogItem(BaseModel):
    id: str
    occurred_at: datetime
    user_email: str
    role: str
    action_type: str
    entity_type: str
    outcome: str
    details: str


class AdminLogsSection(BaseModel):
    total_audit_logs: int = Field(..., ge=0)
    failures_last_24h: int = Field(..., ge=0)
    uploads_last_24h: int = Field(..., ge=0)
    analyses_last_24h: int = Field(..., ge=0)
    security_event_count: int = Field(..., ge=0)
    suspicious_ip_count: int = Field(..., ge=0)
    items: list[AdminLogItem]


class AdminModelsSection(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    current_model_version: str
    total_analyses: int = Field(..., ge=0)
    analyses_last_7_days: int = Field(..., ge=0)
    average_confidence: float = Field(..., ge=0.0, le=1.0)
    input_type_distribution: list[CountItem]
    report_jobs_completed: int = Field(..., ge=0)


class ConsentScopeItem(BaseModel):
    scope: str
    granted_count: int = Field(..., ge=0)
    revoked_count: int = Field(..., ge=0)


class AdminPrivacySection(BaseModel):
    total_consent_records: int = Field(..., ge=0)
    exports_generated: int = Field(..., ge=0)
    audit_events_last_24h: int = Field(..., ge=0)
    hashed_text_storage: bool
    consent_by_scope: list[ConsentScopeItem]


class AdminSettingsSection(BaseModel):
    environment: str
    frontend_url: str
    access_token_expire_minutes: int = Field(..., ge=1)
    rate_limit_per_minute: int = Field(..., ge=1)
    db_auto_create: bool
    health_status: str
    cpu_percent: float = Field(..., ge=0.0)
    memory_percent: float = Field(..., ge=0.0)


class AdminProfileSection(BaseModel):
    email: str
    full_name: str
    role: str
    last_login_at: datetime | None = None
    recent_actions: list[AdminLogItem]


class AdminConsoleResponse(BaseModel):
    users: AdminUsersSection
    logs: AdminLogsSection
    models: AdminModelsSection
    privacy: AdminPrivacySection
    settings: AdminSettingsSection
    profile: AdminProfileSection
