"""
URL SCANNER
===========
Checks URLs against VirusTotal.
"""

import requests
import base64
import time
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")


def scan_url(url, api_key=None):
    api_key = api_key or VT_API_KEY
    headers = {"x-apikey": api_key}

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data  = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless",   0)
            total      = malicious + suspicious + harmless

            return {
                "url":        url,
                "malicious":  malicious,
                "suspicious": suspicious,
                "harmless":   harmless,
                "total":      total,
                "verdict":    get_url_verdict(malicious, suspicious, total),
                "error":      None
            }

        elif response.status_code == 404:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if submit.status_code == 200:
                time.sleep(3)
                return scan_url(url, api_key)
            else:
                return error_result(url, "Could not submit URL")

        else:
            return error_result(url, f"VirusTotal error: {response.status_code}")

    except requests.exceptions.Timeout:
        return error_result(url, "Request timed out")
    except Exception as e:
        return error_result(url, str(e))


def scan_all_urls(urls, api_key=None):
    results = []
    for i, url in enumerate(urls):
        print(f"  Scanning URL {i+1}/{len(urls)}: {url[:60]}...")
        result = scan_url(url, api_key)
        results.append(result)
        if i < len(urls) - 1:
            time.sleep(15)
    return results


def get_url_verdict(malicious, suspicious, total):
    if total == 0:      return "UNKNOWN"
    if malicious >= 3:  return "MALICIOUS"
    if malicious >= 1 or suspicious >= 3: return "SUSPICIOUS"
    return "CLEAN"


def error_result(url, message):
    return {
        "url": url, "malicious": 0, "suspicious": 0,
        "harmless": 0, "total": 0, "verdict": "UNKNOWN", "error": message
    }


def format_url_results(scan_results):
    if not scan_results:
        return "No URLs found in email."
    lines = []
    for r in scan_results:
        if r["error"]:
            lines.append(f"- {r['url']} → Could not scan ({r['error']})")
        else:
            lines.append(
                f"- {r['url']} → {r['verdict']} "
                f"({r['malicious']} malicious, {r['suspicious']} suspicious "
                f"out of {r['total']} engines)"
            )
    return "\n".join(lines)