from collections import defaultdict

# =====================================================
# Reputation Stores
# =====================================================

ip_reputation = defaultdict(int)
user_reputation = defaultdict(int)


# =====================================================
# Reputation Weights
# =====================================================

EVENT_IMPACT = {
    "blocked_input": 10,
    "flagged_input": 7,
    "ai_attack_detected": 25,
    "invalid_token_attempt": 20,
    "revoked_token_used": 30,
    "invalid_token_payload": 15,
    "ip_blocked": 40,
    "blocked_ip_attempt": 20,
}


# =====================================================
# Update Reputation
# =====================================================
def update_reputation(event: dict):

    event_type = event.get("event")
    ip = event.get("ip")
    user = event.get("user")

    impact = EVENT_IMPACT.get(event_type, 5)

    if ip:
        ip_reputation[ip] += impact

    if user:
        user_reputation[user] += impact


# =====================================================
# Get Reputation
# =====================================================
def get_ip_score(ip: str):
    return ip_reputation.get(ip, 0)


def get_user_score(user: str):
    return user_reputation.get(user, 0)


# =====================================================
# Risk Classification
# =====================================================
def classify(score: int):

    if score >= 100:
        return "BLACKLIST"

    if score >= 70:
        return "HIGH_RISK"

    if score >= 40:
        return "SUSPICIOUS"

    return "NORMAL"
