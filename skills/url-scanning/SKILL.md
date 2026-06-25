# URL Scanning Skill

## Trigger
Use this skill when the email contains one or more URLs that need
to be verified against threat intelligence databases.

## Description
Scans URLs extracted from email against VirusTotal which checks
against 70+ antivirus engines and threat databases.

## Steps
1. Extract all URLs from the email body and any anchor text
2. For each URL check against VirusTotal API
3. Record the number of engines that flagged it as malicious
4. Check if the domain is a known URL shortener hiding destination
5. Check if URL domain mismatches the claimed sender organization
6. Return scan results for each URL

## Output Format
- url: the scanned URL
- malicious_count: number of engines that flagged it
- verdict: CLEAN / SUSPICIOUS / MALICIOUS
- note: any additional context

## Risk Thresholds
- 0 engines flagged: CLEAN
- 1-2 engines flagged: SUSPICIOUS
- 3+ engines flagged: MALICIOUS

## Token Budget
Do not include full VirusTotal response. Only return the summary fields above.
