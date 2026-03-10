import logging
import re
from csv import DictReader
from datetime import datetime
from html import unescape as html_unescape
from io import StringIO
from json import loads as json_loads
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse
from urllib.request import Request as UrlRequest, urlopen
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.core.limiter import limiter
from app.core.security_logger import security_log
from app.db.models import AnalysisRequest, AnalysisResult, AuditLog
from app.db.session import get_db
from app.schemas.sentiment import (
    BatchUploadResponse,
    LinkAnalysisRequest,
    LinkAnalysisResponse,
    SentimentRequest,
    SentimentResponse,
)
from app.security.ai_guard import detect_ai_attack
from app.security.input_validator import validate_text_input
from app.security.privacy_guard import hash_metadata
from app.security.rbac import require_permission
from app.services.dashboard_service import refresh_daily_kpi_snapshots
from app.services.sentiment_service import SentimentService

try:
    from youtube_transcript_api import YouTubeTranscriptApi
except Exception:  # pragma: no cover - optional runtime dependency
    YouTubeTranscriptApi = None  # type: ignore[assignment]

logger = logging.getLogger("SAMHM.Sentiment")
router = APIRouter()

DANGEROUS_PATTERNS = re.compile(r"<script|</script>|<.*?>|javascript:", re.IGNORECASE)
SUPPORTED_LINK_HOSTS = {
    "reddit.com": "reddit",
    "www.reddit.com": "reddit",
    "m.reddit.com": "reddit",
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "m.youtube.com": "youtube",
    "youtu.be": "youtube",
}
MAX_BATCH_ROWS = 1000
MAX_BATCH_FILE_BYTES = 10 * 1024 * 1024
TEXT_COLUMN_ALIASES = [
    "text",
    "clean_text",
    "content",
    "message",
    "post",
    "body",
]
DEFAULT_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}
YOUTUBE_CAPTION_TEXT_LIMIT = 1800


def _get_request_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _validate_analysis_text(
    *,
    text: str,
    current_user: dict,
    ip: str,
    allow_flagged_content: bool = False,
) -> None:
    if not text:
        raise HTTPException(400, "Input text cannot be empty.")

    if DANGEROUS_PATTERNS.search(text):
        security_log(
            event="blocked_input",
            user=current_user.get("email"),
            ip=ip,
            reason="html_or_script_detected",
        )
        raise HTTPException(400, "Input contains disallowed content.")

    if not allow_flagged_content:
        validation = validate_text_input(text) or {}
        if validation.get("flagged"):
            security_log(
                event="flagged_input",
                user=current_user.get("email"),
                ip=ip,
                reason=validation.get("reason"),
            )
            raise HTTPException(400, f"Input flagged: {validation.get('reason')}")

        attack = detect_ai_attack(text)
        if attack.get("attack"):
            security_log(
                event="ai_attack_detected",
                user=current_user.get("email"),
                ip=ip,
                type=attack.get("type"),
                risk=attack.get("risk"),
            )
            raise HTTPException(400, f"Input rejected: {attack.get('type')}")


def _persist_analysis(
    *,
    db: Session,
    current_user: dict,
    ip: str,
    input_type: str,
    source_reference: str | None,
    source_platform: str | None,
    text: str,
    request_metadata: dict | None,
    audit_action: str,
) -> tuple[AnalysisRequest, AnalysisResult, dict, object]:
    meta = hash_metadata(text)
    submitted_at = datetime.utcnow()
    inference = SentimentService.analyze(text)

    analysis_request = AnalysisRequest(
        user_id=current_user["id"],
        input_type=input_type,
        source_platform=source_platform,
        source_reference=source_reference,
        text_hash=meta["hash"],
        text_length=meta["length"],
        word_count=meta["word_count"],
        status="completed",
        submitted_at=submitted_at,
        completed_at=submitted_at,
        model_name=inference.model_name,
        model_version=inference.model_version,
        request_metadata=request_metadata,
    )
    db.add(analysis_request)
    db.flush()

    analysis_result = AnalysisResult(
        analysis_request_id=analysis_request.id,
        sentiment_label=inference.sentiment,
        emotion_label=inference.emotion_label,
        confidence_score=inference.confidence,
        explainability_summary=inference.explainability,
        result_metadata={
            "confidence_scale": "0_to_1",
            "raw_label": inference.raw_label,
            "label_scores": inference.label_scores,
            **inference.metadata,
        },
    )
    db.add(analysis_result)
    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type=audit_action,
            entity_type="analysis_request",
            entity_id=analysis_request.id,
            outcome="success",
            ip_address=ip,
            details={
                "input_type": input_type,
                "source_platform": source_platform,
                "model_version": inference.model_version,
                "raw_label": inference.raw_label,
                "text_hash": meta["hash"],
            },
        )
    )

    return analysis_request, analysis_result, meta, inference


def _refresh_kpis_for_user(db: Session, user_id: str) -> None:
    refresh_daily_kpi_snapshots(db)
    refresh_daily_kpi_snapshots(db, user_id=user_id)


def _detect_platform(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    platform = SUPPORTED_LINK_HOSTS.get(host)
    if not platform:
        raise HTTPException(400, "Only Reddit and YouTube links are supported.")
    return platform


def _build_link_preview(url: str, platform: str) -> str:
    parsed = urlparse(url)
    path_tokens = [
        token
        for token in re.split(r"[-_/]+", parsed.path.strip("/"))
        if token and token.lower() not in {"watch", "comments", "r"}
    ]
    query_values: list[str] = []
    for values in parse_qs(parsed.query).values():
        query_values.extend(values)

    normalized_tokens = path_tokens + query_values
    cleaned_tokens = [
        re.sub(r"[^a-zA-Z0-9]+", " ", token).strip()
        for token in normalized_tokens
        if token.strip()
    ]
    preview_body = " ".join(token for token in cleaned_tokens if token)

    if not preview_body:
        preview_body = f"{platform} social media content"

    return (
        f"Normalized {platform} content extracted from submitted link. "
        f"Content hints: {preview_body[:220]}"
    )


def _fetch_url_text(url: str, *, headers: dict[str, str] | None = None) -> tuple[str, str]:
    request_headers = {**DEFAULT_BROWSER_HEADERS, **(headers or {})}
    request = UrlRequest(url, headers=request_headers)
    with urlopen(request, timeout=8) as response:
        return response.read().decode("utf-8", errors="ignore"), response.geturl()


def _compact_text_parts(parts: list[str], *, limit: int = 1200) -> str:
    cleaned_parts: list[str] = []
    total_length = 0

    for part in parts:
        cleaned = re.sub(r"\s+", " ", part or "").strip()
        if not cleaned:
            continue

        remaining = limit - total_length
        if remaining <= 0:
            break

        clipped = cleaned[:remaining].strip()
        if clipped:
            cleaned_parts.append(clipped)
            total_length += len(clipped) + 1

    return " ".join(cleaned_parts).strip()


def _build_row_preview(text: str, *, limit: int = 120) -> str:
    normalized = re.sub(r"\s+", " ", text or "").strip()
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "..."


def _extract_reddit_text(url: str) -> str:
    canonical_url = _resolve_reddit_canonical_url(url)
    parsed = urlparse(canonical_url)
    query_params = parse_qs(parsed.query)
    query_params["raw_json"] = ["1"]
    json_url = (
        f"{parsed.scheme or 'https'}://{parsed.netloc}{parsed.path.rstrip('/')}.json"
        f"?{urlencode(query_params, doseq=True)}"
    )

    payload_text, _ = _fetch_url_text(
        json_url,
        headers={"Accept": "application/json,text/html,application/xhtml+xml,*/*;q=0.8"},
    )
    payload = json_loads(payload_text)
    if not isinstance(payload, list) or not payload:
        raise ValueError("Unexpected Reddit response shape.")

    parts: list[str] = []

    post_listing = payload[0]
    post_children = (((post_listing or {}).get("data") or {}).get("children") or [])
    if post_children:
        post_data = ((post_children[0] or {}).get("data") or {})
        parts.extend(
            [
                str(post_data.get("title") or ""),
                str(post_data.get("selftext") or ""),
                str(post_data.get("subreddit_name_prefixed") or ""),
            ]
        )

    if len(payload) > 1:
        comments_listing = payload[1]
        comment_children = (((comments_listing or {}).get("data") or {}).get("children") or [])
        for child in comment_children[:12]:
            parts.extend(_collect_reddit_comment_bodies(child))

    extracted = _compact_text_parts(parts)
    if not extracted:
        raise ValueError("No Reddit text could be extracted.")

    return extracted


def _resolve_reddit_canonical_url(url: str) -> str:
    parsed = urlparse(url)
    if "/comments/" in parsed.path:
        return url

    _, final_url = _fetch_url_text(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
        },
    )

    final_path = urlparse(final_url).path
    if "/comments/" in final_path:
        return final_url

    return url


def _collect_reddit_comment_bodies(node: dict) -> list[str]:
    if not isinstance(node, dict):
        return []

    kind = node.get("kind")
    data = node.get("data") or {}
    collected: list[str] = []

    if kind == "t1":
        body = str(data.get("body") or "").strip()
        if body:
            collected.append(body)

    replies = data.get("replies")
    if isinstance(replies, dict):
        reply_children = (((replies or {}).get("data") or {}).get("children") or [])
        for child in reply_children[:8]:
            collected.extend(_collect_reddit_comment_bodies(child))

    return collected


def _extract_youtube_video_id(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = (parsed.path or "").strip("/")

    if host in {"youtube.com", "www.youtube.com", "m.youtube.com"}:
        if path == "watch":
            candidate = parse_qs(parsed.query).get("v", [""])[0]
            return candidate[:32] if candidate else None
        if path.startswith("shorts/"):
            return path.split("/", 1)[1][:32]
        if path.startswith("embed/"):
            return path.split("/", 1)[1][:32]

    if host == "youtu.be" and path:
        return path.split("/", 1)[0][:32]

    return None


def _extract_caption_tracks(track_list_xml: str) -> list[dict[str, str]]:
    tracks: list[dict[str, str]] = []
    for match in re.finditer(r"<track\s+([^>]+?)/?>", track_list_xml, re.IGNORECASE):
        attrs_raw = match.group(1)
        attrs: dict[str, str] = {}
        for attr_match in re.finditer(r'([a-zA-Z_]+)="([^"]*)"', attrs_raw):
            attrs[attr_match.group(1)] = html_unescape(attr_match.group(2))

        lang = (attrs.get("lang_code") or "").strip()
        if not lang:
            continue

        tracks.append(
            {
                "lang": lang,
                "kind": (attrs.get("kind") or "").strip(),
                "name": (attrs.get("name") or "").strip(),
            }
        )

    return tracks


def _caption_track_priority(track: dict[str, str]) -> tuple[int, int, int]:
    lang = (track.get("lang") or "").lower()
    kind = (track.get("kind") or "").lower()
    name = (track.get("name") or "").lower()

    english_boost = 2 if lang.startswith("en") else 0
    manual_boost = 1 if kind != "asr" else 0
    no_name_boost = 1 if not name else 0
    return (english_boost, manual_boost, no_name_boost)


def _build_caption_candidate_urls(video_id: str, track_list_xml: str) -> list[str]:
    candidate_urls: list[str] = []
    seen: set[tuple[str, str, str]] = set()

    tracks = _extract_caption_tracks(track_list_xml)
    for track in sorted(tracks, key=_caption_track_priority, reverse=True):
        lang = track.get("lang", "")
        kind = track.get("kind", "")
        name = track.get("name", "")
        key = (lang, kind, name)
        if key in seen:
            continue
        seen.add(key)

        params: dict[str, str] = {"v": video_id, "lang": lang}
        if kind:
            params["kind"] = kind
        if name:
            params["name"] = name

        candidate_urls.append(f"https://www.youtube.com/api/timedtext?{urlencode(params)}")

    # Deterministic fallbacks when track discovery is limited or blocked.
    fallback_params = [
        {"v": video_id, "lang": "en"},
        {"v": video_id, "lang": "en", "kind": "asr"},
        {"v": video_id, "lang": "en-US"},
        {"v": video_id, "lang": "en-US", "kind": "asr"},
    ]
    for params in fallback_params:
        key = (params.get("lang", ""), params.get("kind", ""), params.get("name", ""))
        if key in seen:
            continue
        seen.add(key)
        candidate_urls.append(f"https://www.youtube.com/api/timedtext?{urlencode(params)}")

    return candidate_urls


def _extract_caption_text(captions_xml: str) -> str:
    if "<text" not in captions_xml.lower():
        return ""

    parts: list[str] = []
    for match in re.finditer(r"<text[^>]*>(.*?)</text>", captions_xml, re.IGNORECASE | re.DOTALL):
        segment_html = match.group(1)
        segment_plain = re.sub(r"<[^>]+>", " ", segment_html)
        segment_plain = html_unescape(segment_plain)
        parts.append(segment_plain)

    return _compact_text_parts(parts, limit=YOUTUBE_CAPTION_TEXT_LIMIT)


def _extract_caption_text_json3(captions_json: str) -> str:
    try:
        payload = json_loads(captions_json)
    except Exception:
        return ""

    events = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(events, list):
        return ""

    parts: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        segs = event.get("segs")
        if not isinstance(segs, list):
            continue
        line = "".join(
            str(seg.get("utf8") or "")
            for seg in segs
            if isinstance(seg, dict)
        )
        if line:
            parts.append(line)

    return _compact_text_parts(parts, limit=YOUTUBE_CAPTION_TEXT_LIMIT)


def _extract_caption_payload_text(payload_text: str) -> str:
    trimmed = (payload_text or "").lstrip()
    if not trimmed:
        return ""
    if trimmed.startswith("{"):
        return _extract_caption_text_json3(payload_text)
    return _extract_caption_text(payload_text)


def _extract_caption_base_urls_from_watch_html(html: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(r'"captionTracks"\s*:\s*(\[[^\]]+\])', html, re.DOTALL):
        block = match.group(1)
        try:
            tracks = json_loads(block)
        except Exception:
            continue

        if not isinstance(tracks, list):
            continue

        for track in tracks:
            if not isinstance(track, dict):
                continue
            base_url = str(track.get("baseUrl") or "").strip()
            if not base_url:
                continue
            normalized = html_unescape(base_url).replace("\\u0026", "&")
            if normalized in seen:
                continue
            seen.add(normalized)
            urls.append(normalized)

    return urls


def _fetch_youtube_transcript_with_library(video_id: str) -> str:
    if YouTubeTranscriptApi is None:
        raise ValueError("youtube_transcript_api is not installed.")

    api = YouTubeTranscriptApi()
    fetched = api.fetch(
        video_id,
        languages=["en", "en-US", "en-GB", "en-IN", "en-CA"],
    )
    parts = [str(getattr(item, "text", "") or "") for item in fetched]
    transcript = _compact_text_parts(parts, limit=YOUTUBE_CAPTION_TEXT_LIMIT)
    if not transcript:
        raise ValueError("Empty transcript from youtube_transcript_api.")
    return transcript


def _fetch_youtube_transcript(video_id: str) -> str:
    try:
        return _fetch_youtube_transcript_with_library(video_id)
    except Exception:
        logger.info(
            "youtube_transcript_api transcript fetch failed for video_id=%s; falling back to timedtext",
            video_id,
        )

    track_list_url = f"https://www.youtube.com/api/timedtext?{urlencode({'type': 'list', 'v': video_id})}"
    track_list_xml = ""
    try:
        track_list_xml, _ = _fetch_url_text(track_list_url)
    except Exception:
        logger.info("YouTube caption track list fetch failed for video_id=%s", video_id)

    candidate_urls = _build_caption_candidate_urls(video_id, track_list_xml)
    watch_url = f"https://www.youtube.com/watch?{urlencode({'v': video_id, 'hl': 'en'})}"
    try:
        watch_html, _ = _fetch_url_text(watch_url)
        candidate_urls.extend(_extract_caption_base_urls_from_watch_html(watch_html))
    except Exception:
        logger.info("YouTube watch-page caption extraction failed for video_id=%s", video_id)

    for caption_url in candidate_urls:
        try:
            captions_payload, _ = _fetch_url_text(caption_url)
        except Exception:
            continue

        transcript = _extract_caption_payload_text(captions_payload)
        if transcript:
            return transcript

    raise ValueError("No YouTube transcript could be extracted.")


def _extract_youtube_text(url: str) -> str:
    parts: list[str] = []
    video_id = _extract_youtube_video_id(url)

    if video_id:
        try:
            transcript = _fetch_youtube_transcript(video_id)
            if transcript:
                parts.append(transcript)
        except Exception:
            logger.info("YouTube transcript extraction failed for video_id=%s", video_id)

    oembed_url = f"https://www.youtube.com/oembed?url={quote_plus(url)}&format=json"

    try:
        payload_text, _ = _fetch_url_text(oembed_url)
        payload = json_loads(payload_text)
        if isinstance(payload, dict):
            parts.extend(
                [
                    str(payload.get("title") or ""),
                    str(payload.get("author_name") or ""),
                ]
            )
    except Exception:
        logger.info("YouTube oEmbed extraction failed; trying page HTML fallback")

    if not parts:
        html, _ = _fetch_url_text(url)
        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        description_match = re.search(
            r'<meta\s+name="description"\s+content="([^"]+)"',
            html,
            re.IGNORECASE,
        )
        if title_match:
            parts.append(title_match.group(1))
        if description_match:
            parts.append(description_match.group(1))

    extracted = _compact_text_parts(parts, limit=YOUTUBE_CAPTION_TEXT_LIMIT)
    if not extracted:
        raise ValueError("No YouTube text could be extracted.")

    return extracted


def _extract_link_text(url: str, platform: str) -> tuple[str, str]:
    try:
        if platform == "reddit":
            return _extract_reddit_text(url), "remote_fetch"
        if platform == "youtube":
            return _extract_youtube_text(url), "remote_fetch"
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        logger.warning("Link extraction failed for %s: %s", url, exc)
    except Exception:
        logger.exception("Unexpected link extraction failure for %s", url)

    return _build_link_preview(url, platform), "url_preview_fallback"


@router.post(
    "/analyze", response_model=SentimentResponse, status_code=status.HTTP_200_OK
)
@limiter.limit("10/minute")
def analyze_sentiment(
    request: Request,
    data: SentimentRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("analyze_text")),
):
    timestamp = datetime.utcnow().isoformat()
    ip = _get_request_ip(request)
    text = data.text.strip()

    _validate_analysis_text(text=text, current_user=current_user, ip=ip)
    analysis_request, analysis_result, meta, inference = _persist_analysis(
        db=db,
        current_user=current_user,
        ip=ip,
        input_type="text",
        source_reference=None,
        source_platform=None,
        text=text,
        request_metadata={
            "source": "text_input",
            "input_preview": _build_row_preview(text, limit=280),
        },
        audit_action="analyze_text",
    )

    _refresh_kpis_for_user(db, current_user["id"])
    db.commit()

    logger.info(
        {
            "event": "sentiment_analyzed",
            "user": current_user.get("email"),
            "ip": ip,
            "text_hash": meta["hash"],
            "length": meta["length"],
            "word_count": meta["word_count"],
            "sentiment": analysis_result.sentiment_label,
            "confidence": analysis_result.confidence_score,
            "model_version": inference.model_version,
            "time": timestamp,
        }
    )

    return SentimentResponse(
        analysis_id=analysis_request.id,
        sentiment=analysis_result.sentiment_label,
        emotion=analysis_result.emotion_label,
        confidence=analysis_result.confidence_score,
        version=inference.model_version,
        model_name=inference.model_name,
        label_scores=inference.label_scores,
        result_metadata=analysis_result.result_metadata or {},
    )


@router.post(
    "/analyze-link",
    response_model=LinkAnalysisResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("10/minute")
def analyze_link_sentiment(
    request: Request,
    data: LinkAnalysisRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("analyze_text")),
):
    ip = _get_request_ip(request)
    url = data.url.strip()
    platform = _detect_platform(url)
    extracted_text, extraction_mode = _extract_link_text(url, platform)

    _validate_analysis_text(
        text=extracted_text,
        current_user=current_user,
        ip=ip,
        allow_flagged_content=True,
    )
    analysis_request, analysis_result, _meta, inference = _persist_analysis(
        db=db,
        current_user=current_user,
        ip=ip,
        input_type="link",
        source_reference=url,
        source_platform=platform,
        text=extracted_text,
        request_metadata={
            "source": "social_link",
            "url_host": urlparse(url).netloc.lower(),
            "extraction_mode": extraction_mode,
            "extracted_text_preview": _build_row_preview(extracted_text, limit=520),
        },
        audit_action="analyze_link",
    )

    _refresh_kpis_for_user(db, current_user["id"])
    analysis_result.result_metadata = {
        **(analysis_result.result_metadata or {}),
        "extraction_mode": extraction_mode,
        "source_platform": platform,
    }
    db.commit()

    logger.info(
        {
            "event": "link_sentiment_analyzed",
            "user": current_user.get("email"),
            "ip": ip,
            "platform": platform,
            "analysis_id": analysis_request.id,
        }
    )

    return LinkAnalysisResponse(
        analysis_id=analysis_request.id,
        sentiment=analysis_result.sentiment_label,
        emotion=analysis_result.emotion_label,
        confidence=analysis_result.confidence_score,
        version=inference.model_version,
        model_name=inference.model_name,
        label_scores=inference.label_scores,
        result_metadata=analysis_result.result_metadata or {},
        url=url,
        source_platform=platform,
        extracted_text=extracted_text,
        extracted_text_preview=extracted_text[:280],
    )


@router.post(
    "/batch-upload",
    response_model=BatchUploadResponse,
    status_code=status.HTTP_200_OK,
)
@limiter.limit("5/minute")
async def batch_upload_sentiment(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("analyze_text")),
):
    ip = _get_request_ip(request)
    file_name = file.filename or "batch-upload.csv"

    if not file_name.lower().endswith(".csv"):
        raise HTTPException(400, "Only CSV files are supported.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(400, "Uploaded file is empty.")

    if len(raw_bytes) > MAX_BATCH_FILE_BYTES:
        raise HTTPException(400, "CSV file exceeds the 10 MB limit.")

    try:
        decoded_csv = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "CSV must be UTF-8 encoded.") from exc

    reader = DictReader(StringIO(decoded_csv))
    normalized_to_original: dict[str, str] = {}
    for field in (reader.fieldnames or []):
        if not field:
            continue
        normalized = field.strip().lower()
        if normalized and normalized not in normalized_to_original:
            normalized_to_original[normalized] = field

    text_column = next(
        (normalized_to_original.get(alias) for alias in TEXT_COLUMN_ALIASES if alias in normalized_to_original),
        None,
    )
    if not text_column:
        raise HTTPException(
            400,
            'CSV must include one of these columns: "text", "clean_text", "content", "message", "post", or "body".',
        )

    batch_id = str(uuid4())
    total_rows = 0
    processed_rows = 0
    failed_rows = 0
    created_analysis_ids: list[str] = []

    for row_number, row in enumerate(reader, start=2):
        total_rows += 1
        if total_rows > MAX_BATCH_ROWS:
            raise HTTPException(400, f"CSV exceeds the maximum of {MAX_BATCH_ROWS} rows.")

        text = (row.get(text_column) or "").strip()
        if not text:
            failed_rows += 1
            continue

        try:
            _validate_analysis_text(text=text, current_user=current_user, ip=ip)
            row_preview = _build_row_preview(text)
            analysis_request, _analysis_result, _meta, _inference = _persist_analysis(
                db=db,
                current_user=current_user,
                ip=ip,
                input_type="batch",
                source_reference=file_name,
                source_platform=None,
                text=text,
                request_metadata={
                    "source": "batch_upload",
                    "batch_id": batch_id,
                    "file_name": file_name,
                    "row_number": row_number,
                    "text_column": text_column,
                    "row_preview": row_preview,
                },
                audit_action="batch_upload_analysis",
            )
            created_analysis_ids.append(analysis_request.id)
            processed_rows += 1
        except HTTPException:
            failed_rows += 1

    db.add(
        AuditLog(
            user_id=current_user["id"],
            action_type="batch_upload",
            entity_type="batch_upload",
            entity_id=batch_id,
            outcome="success" if processed_rows else "failed",
            ip_address=ip,
            details={
                "file_name": file_name,
                "total_rows": total_rows,
                "processed_rows": processed_rows,
                "failed_rows": failed_rows,
            },
        )
    )

    if processed_rows:
        _refresh_kpis_for_user(db, current_user["id"])

    db.commit()

    logger.info(
        {
            "event": "batch_upload_processed",
            "user": current_user.get("email"),
            "ip": ip,
            "batch_id": batch_id,
            "processed_rows": processed_rows,
            "failed_rows": failed_rows,
        }
    )

    return BatchUploadResponse(
        batch_id=batch_id,
        file_name=file_name,
        total_rows=total_rows,
        processed_rows=processed_rows,
        failed_rows=failed_rows,
        created_analysis_ids=created_analysis_ids,
    )
