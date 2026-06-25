# Domain Reputation Skill

## Trigger
Use this skill when the sender domain is unknown, suspicious, or
does not match the organization claimed in the email body.

## Description
Checks sender domain age and registration details via WHOIS lookup.
Newly registered domains are a strong phishing indicator.

## Steps
1. Extract the domain from the sender email address
2. Perform WHOIS lookup on the domain
3. Check domain registration date
4. Check if domain is less than 30 days old
5. Check if registrant information is hidden or anonymized
6. Check if domain closely resembles a legitimate brand domain
   (e.g. paypa1.com vs paypal.com)
7. Return domain reputation assessment

## Output Format
- domain: the checked domain
- age_days: how many days since registration
- registrant: public or hidden
- typosquat_detected: true / false
- risk_level: LOW / MEDIUM / HIGH

## Risk Thresholds
- Domain older than 1 year, public registrant: LOW
- Domain 30-365 days old: MEDIUM  
- Domain less than 30 days old: HIGH
- Typosquatting detected: always HIGH

## Token Budget
Return only the output fields above. Do not return raw WHOIS data.
