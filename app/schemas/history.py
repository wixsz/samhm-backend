from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class HistoryItem(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    analysis_id: str = Field(..., description="Analysis request identifier.")
    input_type: str = Field(..., description="Source input type.")
    preview: str = Field(..., description="Privacy-safe preview text.")
    sentiment: str = Field(..., description="Predicted sentiment label.")
    emotion: str | None = Field(default=None, description="Predicted emotion label.")
    confidence: float = Field(..., ge=0.0, le=1.0)
    submitted_at: datetime = Field(..., description="Submission timestamp.")
    model_version: str | None = Field(default=None, description="Model version.")
    row_number: int | None = Field(
        default=None, ge=1, description="Batch CSV row number when applicable."
    )
    source_reference: str | None = Field(
        default=None,
        description="Original source reference (for example, link URL or batch file name).",
    )
    source_platform: str | None = Field(
        default=None,
        description="Detected source platform when available.",
    )
    batch_id: str | None = Field(
        default=None,
        description="Batch identifier for batch-upload records.",
    )
    input_preview: str | None = Field(
        default=None,
        description="Stored preview of original input text when available.",
    )
    extracted_text_preview: str | None = Field(
        default=None,
        description="Stored extracted text preview for link analysis when available.",
    )
    label_scores: dict[str, float] | None = Field(
        default=None,
        description="Raw model label scores when available.",
    )
    runtime: str | None = Field(
        default=None,
        description="Runtime backend marker from result metadata.",
    )


class HistoryResponse(BaseModel):
    items: list[HistoryItem]
    total: int = Field(..., ge=0)
