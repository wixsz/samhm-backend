import logging
from datetime import datetime
from typing import Tuple

from app.security.security_events import log_security_event
from app.security.reputation_engine import update_reputation
from app.monitoring.engine import metrics_engine

logger = logging.getLogger("SAMHM.Security")

RISK_WEIGHTS = {
    "blocked_input": 40,
    "flagged_input": 35,
    "ai_attack_detected": 75,
    "invalid_token_attempt": 60,
    "revoked_token_used": 80,
    "invalid_token_payload": 50,
    "token_revoked": 20,
    "ip_blocked": 85,
    "blocked_ip_attempt": 65,
}


def calculate_risk(event: str, extra_score: int = 0) -> Tuple[int, str]:
    base = RISK_WEIGHTS.get(event, 25)
    score = min(base + extra_score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


def security_log(
    event: str, level: str = "warning", risk_bonus: int = 0, **kwargs
) -> None:

    try:
        metrics_engine.security(event)
    except Exception as exc:
        logger.error("Metrics engine failed: %s", exc)

    score, risk_level = calculate_risk(event, risk_bonus)

    record = {
        "event": event,
        "risk_score": score,
        "risk_level": risk_level,
        "timestamp": datetime.utcnow().isoformat(),
        **kwargs,
    }

    try:
        update_reputation(record)
    except Exception as exc:
        logger.error("Reputation engine failed: %s", exc)

    log_method = {
        "critical": logger.critical,
        "error": logger.error,
        "info": logger.info,
        "warning": logger.warning,
    }.get(level.lower(), logger.warning)

    log_method(record)

    try:
        log_security_event(record)
    except Exception as exc:
        logger.error("Security event storage failed: %s", exc)
