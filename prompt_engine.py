"""
LLM PROMPT ENGINE
=================
Takes parsed email data, scans URLs, sends to Groq AI.
Returns structured verdict.
"""

import json
import re
import os
from groq import Groq
from url_scanner import scan_all_urls, format_url_results
from dotenv import load_dotenv

load_dotenv()

API_KEY    = os.getenv("GROQ_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")


def analyze_email(parsed_email, api_key=None, vt_api_key=None):

    api_key    = api_key    or API_KEY
    vt_api_key = vt_api_key or VT_API_KEY

    client = Groq(api_key=api_key)

    url_report = "No URLs found in email."
    if parsed_email["urls"]:
        print(f"  Found {len(parsed_email['urls'])} URL(s). Scanning with VirusTotal...")
        scan_results = scan_all_urls(parsed_email["urls"], api_key=vt_api_key)
        url_report   = format_url_results(scan_results)

    prompt = f"""
You are a cybersecurity expert specializing in phishing email detection.

Analyze the email below and return ONLY a JSON object. No extra text.

EMAIL TO ANALYZE:
-----------------
Sender  : {parsed_email['sender']}
Subject : {parsed_email['subject']}
Body    : {parsed_email['body']}
Signals : {parsed_email['signals']}

URL SCAN RESULTS (from VirusTotal):
{url_report}
-----------------

Return this exact JSON format:
{{
  "verdict": "PHISHING" or "LEGITIMATE",
  "risk_score": "Low" or "Medium" or "High",
  "explanation": "2-3 sentence plain English explanation",
  "red_flags": ["list", "of", "red", "flags"]
}}

Rules:
- verdict must be exactly PHISHING or LEGITIMATE
- risk_score must be exactly Low, Medium, or High
- If LEGITIMATE, red_flags should be []
- Consider VirusTotal URL results heavily in your decision
- Return ONLY the JSON, nothing else
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": "You are a cybersecurity expert. You only respond with valid JSON."},
            {"role": "user",   "content": prompt}
        ],
        temperature=0.1,
        max_tokens=500,
    )

    raw_response = response.choices[0].message.content.strip()
    return parse_response(raw_response)


def parse_response(raw_text):
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    match = re.search(r'\{.*\}', raw_text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    return {
        "verdict":     "UNKNOWN",
        "risk_score":  "Unknown",
        "explanation": "Could not parse AI response.",
        "red_flags":   []
    }