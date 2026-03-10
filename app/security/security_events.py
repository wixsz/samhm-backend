from datetime import datetime
from typing import Dict, List

# =====================================================
# In-Memory Security Event Store
# =====================================================

SECURITY_EVENTS: List[Dict] = []

MAX_EVENTS = 1000


def log_security_event(event: Dict):
    """
    Store structured security events.
    """

    event["timestamp"] = datetime.utcnow().isoformat()

    SECURITY_EVENTS.append(event)

    # keep memory bounded
    if len(SECURITY_EVENTS) > MAX_EVENTS:
        SECURITY_EVENTS.pop(0)


# =====================================================
# Query Functions
# =====================================================


def get_all_events():
    return SECURITY_EVENTS


def get_events_by_type(event_type: str):
    return [e for e in SECURITY_EVENTS if e.get("event") == event_type]


def get_attack_summary():
    summary = {}

    for e in SECURITY_EVENTS:
        key = e.get("event")
        summary[key] = summary.get(key, 0) + 1

    return summary


def get_suspicious_ips():
    counter = {}

    for e in SECURITY_EVENTS:
        ip = e.get("ip")
        if not ip:
            continue

        counter[ip] = counter.get(ip, 0) + 1

    return sorted(counter.items(), key=lambda x: x[1], reverse=True)
