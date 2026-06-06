"""
EMAIL PARSER
============
Takes one email (sender, subject, body) and extracts:
- Clean sender address
- Subject line
- Body text
- All URLs found in body
- Suspicious signals (domain spoofing, urgency language, sensitive info requests)

Used in: Flask backend (app.py) before sending email to LLM
"""

import re


def extract_urls(text):
    """Pull all URLs from a block of text."""
    if not isinstance(text, str):
        return []
    pattern = r'https?://[^\s<>"\']+'
    urls = re.findall(pattern, text)
    return list(set(urls))


def detect_signals(sender, subject, body):
    """
    Look for common phishing signals.
    Returns a list of warning strings.
    """
    signals = []

    if isinstance(sender, str):
        domain_match = re.search(r'@([\w.-]+)', sender)
        if domain_match:
            domain = domain_match.group(1).lower()
            brands = {
                "paypal": "paypal.com", "google": "google.com",
                "amazon": "amazon.com", "microsoft": "microsoft.com",
                "apple": "apple.com",   "fedex": "fedex.com",
                "netflix": "netflix.com", "chase": "chase.com",
            }
            for brand, real_domain in brands.items():
                if brand in domain and domain != real_domain:
                    signals.append(f"Possible impersonation: '{domain}' pretending to be '{real_domain}'")

            for tld in [".xyz", ".ru", ".info", ".win", ".click", ".top", ".tk"]:
                if domain.endswith(tld):
                    signals.append(f"Suspicious sender domain TLD: '{domain}'")
                    break

    if isinstance(subject, str):
        urgency_words = ["urgent", "immediately", "suspended", "verify", "limited",
                         "expire", "action required", "warning", "account locked"]
        found = [w for w in urgency_words if w in subject.lower()]
        if found:
            signals.append(f"Urgency language in subject: {found}")

    if isinstance(body, str):
        urgency_phrases = ["within 24 hours", "immediately", "act now",
                           "click here to verify", "update your information"]
        found_phrases = [p for p in urgency_phrases if p in body.lower()]
        if found_phrases:
            signals.append(f"Urgency phrases in body: {found_phrases}")

        sensitive = ["social security", "credit card", "bank account", "password"]
        found_sensitive = [s for s in sensitive if s in body.lower()]
        if found_sensitive:
            signals.append(f"Requests sensitive information: {found_sensitive}")

        for url in extract_urls(body):
            domain_match = re.search(r'https?://([\w.-]+)', url)
            if domain_match:
                url_domain = domain_match.group(1).lower()
                for tld in [".xyz", ".ru", ".info", ".win", ".click"]:
                    if url_domain.endswith(tld):
                        signals.append(f"Suspicious URL: {url}")
                        break

    return signals


def parse_email(sender, subject, body):
    """
    Main function. Takes sender, subject, body strings.
    Returns a clean dictionary ready to send to the LLM.
    """
    sender  = str(sender).strip()  if sender  else "unknown"
    subject = str(subject).strip() if subject else "(no subject)"
    body    = str(body).strip()    if body    else ""

    return {
        "sender":  sender,
        "subject": subject,
        "body":    body[:3000],
        "urls":    extract_urls(body),
        "signals": detect_signals(sender, subject, body),
    }


if __name__ == "__main__":
    import pandas as pd

    print("Testing parser on real_email_dataset.csv\n")
    df = pd.read_csv("real_email_dataset.csv")

    phishing   = df[df["label"] == "phishing"].head(3)
    legitimate = df[df["label"] == "legitimate"].head(3)

    for _, row in pd.concat([phishing, legitimate]).iterrows():
        result = parse_email(row["sender"], row["subject"], row["body"])
        print("=" * 55)
        print(f"LABEL   : {row['label'].upper()}")
        print(f"SENDER  : {result['sender']}")
        print(f"SUBJECT : {result['subject']}")
        print(f"BODY    : {result['body'][:100]}...")
        print(f"URLS    : {result['urls']}")
        print(f"SIGNALS : {result['signals']}")
        print()