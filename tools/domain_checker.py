"""
Domain Reputation Checker
Checks sender domain age and registration via WHOIS lookup.
Newly registered domains are a strong phishing indicator.
"""

import re
from datetime import datetime, timezone

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


KNOWN_LEGITIMATE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "stackoverflow.com"
]

TYPOSQUAT_TARGETS = [
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "twitter", "linkedin", "netflix", "spotify",
    "instagram", "whatsapp", "telegram", "gmail", "yahoo"
]


def extract_domain(email_address: str) -> str:
    """Extract domain from email address."""
    if "@" in email_address:
        return email_address.split("@")[-1].lower().strip()
    # If it's already a domain
    return email_address.lower().strip()


def check_typosquatting(domain: str) -> bool:
    """
    Check if domain closely resembles a known legitimate domain.
    Simple character substitution detection.
    """
    domain_base = domain.split(".")[0].lower()
    
    for target in TYPOSQUAT_TARGETS:
        # Exact match is legitimate
        if domain_base == target:
            return False
        
        # Check character substitutions like paypa1 vs paypal
        if len(domain_base) == len(target):
            differences = sum(
                1 for a, b in zip(domain_base, target) if a != b
            )
            if differences == 1:
                return True
        
        # Check if target is contained with extra chars
        if target in domain_base and domain_base != target:
            return True
            
    return False


def check_domain(sender_email: str) -> dict:
    """
    Check domain reputation for a sender email address.
    
    Returns:
        dict with domain reputation assessment
    """
    domain = extract_domain(sender_email)
    
    # Skip check for known legitimate domains
    if domain in KNOWN_LEGITIMATE_DOMAINS:
        return {
            "domain": domain,
            "age_days": 9999,
            "registrant": "public",
            "typosquat_detected": False,
            "risk_level": "LOW",
            "note": "Known legitimate domain"
        }
    
    # Check typosquatting first
    typosquat = check_typosquatting(domain)
    
    # Try WHOIS lookup
    age_days = None
    registrant = "unknown"
    
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                
                now = datetime.now(timezone.utc)
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                    
                age_days = (now - creation).days
            
            if w.registrant_name or w.org:
                registrant = "public"
            else:
                registrant = "hidden"
                
        except Exception:
            age_days = None
            registrant = "unknown"
    
    # Calculate risk level
    risk_level = "LOW"
    
    if typosquat:
        risk_level = "HIGH"
    elif age_days is not None:
        if age_days < 30:
            risk_level = "HIGH"
        elif age_days < 365:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    elif registrant == "hidden":
        risk_level = "MEDIUM"
    
    return {
        "domain": domain,
        "age_days": age_days,
        "registrant": registrant,
        "typosquat_detected": typosquat,
        "risk_level": risk_level,
        "note": "WHOIS lookup performed" if WHOIS_AVAILABLE else "WHOIS not available, typosquat check only"
    }
