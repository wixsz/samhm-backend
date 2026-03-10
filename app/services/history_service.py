from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AnalysisRequest, AnalysisResult


def build_history_response(
    db: Session,
    *,
    user_id: str,
    limit: int = 50,
) -> dict:
    rows = db.execute(
        select(AnalysisRequest, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.analysis_request_id == AnalysisRequest.id)
        .where(
            AnalysisRequest.user_id == user_id,
            AnalysisRequest.status == "completed",
        )
        .order_by(AnalysisRequest.submitted_at.desc())
        .limit(limit)
    ).all()

    items = []
    for request, result in rows:
        metadata = request.request_metadata or {}
        result_metadata = result.result_metadata or {}
        row_number = metadata.get("row_number")
        row_preview = metadata.get("row_preview")
        input_preview = metadata.get("input_preview")
        extracted_text_preview = metadata.get("extracted_text_preview")
        batch_id = metadata.get("batch_id")
        label_scores = result_metadata.get("label_scores")
        runtime = result_metadata.get("runtime")
        if isinstance(row_preview, str) and row_preview.strip():
            preview = row_preview.strip()
        elif request.source_reference:
            preview = request.source_reference
        elif request.text_hash:
            preview = f"text hash {request.text_hash[:12]}"
        else:
            preview = "analysis record"

        normalized_row_number = (
            row_number
            if isinstance(row_number, int) and row_number > 0
            else None
        )
        items.append(
            {
                "analysis_id": request.id,
                "input_type": request.input_type,
                "preview": preview,
                "sentiment": result.sentiment_label,
                "emotion": result.emotion_label,
                "confidence": result.confidence_score,
                "submitted_at": request.submitted_at,
                "model_version": request.model_version,
                "row_number": normalized_row_number,
                "source_reference": request.source_reference,
                "source_platform": request.source_platform,
                "batch_id": batch_id if isinstance(batch_id, str) and batch_id.strip() else None,
                "input_preview": input_preview if isinstance(input_preview, str) and input_preview.strip() else None,
                "extracted_text_preview": extracted_text_preview
                if isinstance(extracted_text_preview, str) and extracted_text_preview.strip()
                else None,
                "label_scores": label_scores if isinstance(label_scores, dict) else None,
                "runtime": runtime if isinstance(runtime, str) and runtime.strip() else None,
            }
        )

    return {"items": items, "total": len(items)}
