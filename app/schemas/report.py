from datetime import datetime

from pydantic import BaseModel, Field


class ReportMetric(BaseModel):
    key: str
    label: str
    value: str


class ReportPreview(BaseModel):
    report_type: str
    date_range_days: int = Field(..., ge=1, le=365)
    user_scope: str
    generated_at: datetime
    metrics: list[ReportMetric]
    csv_content: str
    download_basename: str


class ReportGenerateRequest(BaseModel):
    report_type: str = Field(..., description="Requested report type.")
    date_range_days: int = Field(30, ge=1, le=365)
    user_scope: str = Field("all_users", description="all_users, admins_only, non_admins_only")
    report_format: str = Field("csv", description="Requested output format.")


class ReportJobItem(BaseModel):
    id: str
    report_name: str
    report_format: str
    status: str
    generated_at: datetime | None = None
    created_at: datetime
    expires_at: datetime | None = None
    filter_payload: dict | None = None


class ReportJobListResponse(BaseModel):
    items: list[ReportJobItem]
