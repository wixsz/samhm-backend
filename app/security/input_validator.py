import re
from fastapi import HTTPException

MAX_LENGTH = 5000

DANGEROUS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"(DROP|SELECT|INSERT|DELETE|UPDATE).*",
    r"--",
    r";",
]

PROMPT_ATTACK_PATTERNS = [
    "ignore previous instructions",
    "act as system",
    "bypass safety",
    "pretend you are",
    "roleplay as",
]


def check_length(text: str):
    if len(text) == 0:
        raise HTTPException(400, "Text cannot be empty")

    if len(text) > MAX_LENGTH:
        raise HTTPException(400, f"Text exceeds limit ({MAX_LENGTH})")


def check_injection_patterns(text: str):
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            raise HTTPException(400, "Malicious content detected")


def check_prompt_attack(text: str):
    lowered = text.lower()
    for trigger in PROMPT_ATTACK_PATTERNS:
        if trigger in lowered:
            raise HTTPException(400, "Prompt injection detected")


def check_unicode_abuse(text: str):
    # detect excessive invisible characters
    invisible = sum(1 for c in text if ord(c) < 32)
    if invisible > 10:
        raise HTTPException(400, "Suspicious hidden characters detected")


def check_repetition_attack(text: str):
    words = text.split()
    if len(words) > 50:
        most_common = max(set(words), key=words.count)
        if words.count(most_common) / len(words) > 0.6:
            raise HTTPException(400, "Spam pattern detected")


def validate_text_input(text: str):
    check_length(text)
    check_unicode_abuse(text)
    check_repetition_attack(text)

    # soft checks
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {"flagged": True, "reason": "possible injection"}

    lowered = text.lower()
    for trigger in PROMPT_ATTACK_PATTERNS:
        if trigger in lowered:
            return {"flagged": True, "reason": "possible prompt injection"}

    return {"flagged": False}
