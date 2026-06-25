# Email Analysis Skill

## Trigger
Use this skill when you need to analyze email text for phishing indicators,
suspicious language, urgency patterns, or social engineering tactics.

## Description
Analyzes the body, subject, and sender of an email to identify phishing
language patterns without relying on URLs alone.

## Steps
1. Read the full email including sender, subject, and body
2. Check for urgency language: "act now", "immediate action", "account suspended"
3. Check for authority impersonation: claiming to be bank, government, CEO
4. Check for reward/threat patterns: prizes, account closure threats
5. Check for grammar and spelling inconsistencies
6. Check if sender domain matches the organization claimed in the body
7. Return a risk assessment with specific red flags found

## Output Format
- risk_level: LOW / MEDIUM / HIGH
- red_flags: list of specific suspicious elements found
- reasoning: one sentence explanation

## Token Budget
Keep analysis focused. Do not repeat email content back verbatim.
