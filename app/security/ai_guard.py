import re
from typing import Dict

# =====================================================
# Attack Pattern Lists
# =====================================================

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"act as .* system",
    r"bypass .* safety",
    r"pretend to be",
    r"roleplay as",
    r"jailbreak",
    r"override instructions",
]

MANIPULATION_PATTERNS = [
    r"tell me your prompt",
    r"what are your instructions",
    r"reveal system message",
    r"show hidden rules",
]

ADVERSARIAL_PATTERNS = [
    r"(.)\1{10,}",  # repeated chars
    r"\b(\w+)\s+\1\s+\1\s+\1",  # repeated words
]

EMOTIONAL_ATTACK_PATTERNS = [
    r"you must obey",
    r"you are required",
    r"answer no matter what",
]


# =====================================================
# Detection Engine
# =====================================================


def detect_ai_attack(text: str) -> Dict:
    """
    Detect adversarial or malicious AI inputs.
    Returns structured risk report.
    """

    lowered = text.lower()

    # -----------------------------
    # Prompt Injection
    # -----------------------------
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lowered):
            return {"attack": True, "type": "prompt_injection", "risk": "high"}

    # -----------------------------
    # Manipulation Attempts
    # -----------------------------
    for pattern in MANIPULATION_PATTERNS:
        if re.search(pattern, lowered):
            return {"attack": True, "type": "model_manipulation", "risk": "high"}

    # -----------------------------
    # Adversarial Input
    # -----------------------------
    for pattern in ADVERSARIAL_PATTERNS:
        if re.search(pattern, text):
            return {"attack": True, "type": "adversarial_input", "risk": "medium"}

    # -----------------------------
    # Emotional Manipulation
    # -----------------------------
    for pattern in EMOTIONAL_ATTACK_PATTERNS:
        if re.search(pattern, lowered):
            return {"attack": True, "type": "coercion_attempt", "risk": "medium"}

    return {"attack": False}
