import logging
from datetime import datetime
from app.security.security_events import log_security_event

logger = logging.getLogger("SAMHM.Security")


# =====================================================
# Risk Weights Per Event
# =====================================================
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


# =====================================================
# Risk Level Calculator
# =====================================================
def calculate_risk(event: str, extra_score: int = 0):

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


# =====================================================
# Central Security Logger
# =====================================================
def security_log(event: str, level: str = "warning", risk_bonus: int = 0, **kwargs):

    score, risk_level = calculate_risk(event, risk_bonus)

    record = {
        "event": event,
        "risk_score": score,
        "risk_level": risk_level,
        "time": datetime.utcnow().isoformat(),
        **kwargs,
    }

    # -----------------------------
    # Write to log output
    # -----------------------------
    if level == "critical":
        logger.critical(record)
    elif level == "error":
        logger.error(record)
    elif level == "info":
        logger.info(record)
    else:
        logger.warning(record)

    # -----------------------------
    # Store event
    # -----------------------------
    try:
        log_security_event(record)
    except Exception:
        logger.error("Security event storage failed")
