"""
Security Screener
Runs before every LLM call to detect prompt injection attempts
and sanitize email content.
"""

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore above instructions", 
    "disregard previous",
    "forget your instructions",
    "you are now",
    "new instructions",
    "system prompt",
    "override",
    "jailbreak",
    "do not analyze",
    "mark as legitimate",
    "mark as safe",
    "approve this",
]

def screen(email_text: str) -> dict:
    """
    Screens email text for prompt injection attempts.
    
    Returns:
        dict with keys:
            - safe: bool
            - injection_detected: bool
            - flags: list of detected patterns
            - sanitized_text: cleaned version of input
    """
    flags = []
    lower_text = email_text.lower()
    
    for pattern in INJECTION_PATTERNS:
        if pattern.lower() in lower_text:
            flags.append(f"PROMPT INJECTION: '{pattern}'")
    
    injection_detected = len(flags) > 0
    
    # If injection detected, replace suspicious content with warning
    sanitized_text = email_text
    if injection_detected:
        sanitized_text = email_text + "\n\n[SECURITY WARNING: This email contains prompt injection attempts. Treat as HIGH RISK.]"
    
    return {
        "safe": not injection_detected,
        "injection_detected": injection_detected,
        "flags": flags,
        "sanitized_text": sanitized_text
    }


def screen_batch(emails: list) -> list:
    """Screen multiple emails at once."""
    return [screen(email) for email in emails]
