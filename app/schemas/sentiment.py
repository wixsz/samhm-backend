from typing import Any

from pydantic import BaseModel, ConfigDict, Field, validator


# =====================================================
# Request Schema
# =====================================================
class SentimentRequest(BaseModel):
    """
    Input schema for sentiment analysis.
    Enforces strict validation to prevent abuse and misuse.
    """

    text: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Text input for sentiment analysis (max 1000 characters).",
        example="I feel hopeful and motivated today.",
    )

    @validator("text")
    def validate_text(cls, value: str) -> str:
        """
        Prevent empty, whitespace-only, or null-equivalent inputs.
        """
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Text cannot be empty or whitespace.")

        return cleaned


class LinkAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=10,
        max_length=1024,
        description="Supported social media URL for lightweight analysis.",
        example="https://www.reddit.com/r/example/comments/abc123/sample-post/",
    )

    @validator("url")
    def validate_url(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("URL cannot be empty.")

        return cleaned


# =====================================================
# Response Schema
# =====================================================
class SentimentResponse(BaseModel):
    """
    Output schema for sentiment analysis results.
    """

    model_config = ConfigDict(protected_namespaces=())

    analysis_id: str = Field(
        ...,
        description="Stored analysis record identifier.",
        example="a38af6c5-8c0b-45c4-9a28-46f09c6c5a1d",
    )
    sentiment: str = Field(
        ..., description="Predicted sentiment label.", example="positive"
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0 and 1.",
        example=0.87,
    )

    emotion: str | None = Field(
        default=None,
        description="Optional raw model label when it differs from the normalized sentiment.",
        example="depression",
    )

    version: str = Field(
        ..., description="Sentiment model version used for inference.", example="v1.0.0"
    )

    model_name: str = Field(
        ..., description="Backend model name used for inference.", example="sentiment_service"
    )

    label_scores: dict[str, float] = Field(
        default_factory=dict,
        description="Optional class probability map when the model exposes per-label scores.",
    )

    result_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional backend metadata captured during inference.",
    )


class LinkAnalysisResponse(SentimentResponse):
    url: str = Field(..., description="Submitted source URL.")
    source_platform: str = Field(..., description="Detected platform.")
    extracted_text: str = Field(
        ...,
        description="Full extracted or normalized text that was sent to the model.",
    )
    extracted_text_preview: str = Field(
        ...,
        description="Privacy-safe preview of the extracted or normalized text.",
    )


class BatchUploadResponse(BaseModel):
    batch_id: str = Field(..., description="Batch ingestion identifier.")
    file_name: str = Field(..., description="Original uploaded file name.")
    total_rows: int = Field(..., ge=0, description="Total rows encountered in the CSV.")
    processed_rows: int = Field(..., ge=0, description="Rows successfully analyzed.")
    failed_rows: int = Field(..., ge=0, description="Rows rejected during validation.")
    created_analysis_ids: list[str] = Field(
        default_factory=list,
        description="Created analysis request identifiers.",
    )
