from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DistributionItem(BaseModel):
    label: str = Field(..., description="Distribution bucket label.")
    count: int = Field(..., ge=0, description="Number of records in the bucket.")
    percentage: float = Field(..., ge=0.0, le=100.0, description="Bucket percentage.")


class DailyTrendItem(BaseModel):
    date: str = Field(..., description="UTC date bucket in YYYY-MM-DD format.")
    analyses: int = Field(..., ge=0, description="Number of analyses for the day.")
    average_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Average confidence for the day.",
    )


class RecentAnalysisItem(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    analysis_id: str
    input_type: str
    sentiment: str
    emotion: str | None = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    submitted_at: datetime
    model_version: str | None = None


class DashboardSummary(BaseModel):
    total_analyses: int = Field(..., ge=0)
    average_confidence: float = Field(..., ge=0.0, le=1.0)
    distinct_users: int = Field(..., ge=0)
    sentiment_distribution: list[DistributionItem]
    emotion_distribution: list[DistributionItem]
    input_type_distribution: list[DistributionItem]
    daily_trends: list[DailyTrendItem]
    recent_analyses: list[RecentAnalysisItem]
