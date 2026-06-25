# Verdict Generation Skill

## Trigger
Use this skill when you have gathered enough signals from other skills
and tools to produce a final verdict on the email.

## Description
Combines all evidence gathered during analysis to produce a final
structured verdict with confidence score and explanation.

## Steps
1. Collect all results from tools used during this analysis
2. Count total risk signals found across all tools
3. Weight signals by severity:
   - URL flagged by 3+ engines: +3 points
   - Domain less than 30 days old: +2 points
   - Prompt injection detected: +3 points
   - Urgency language found: +1 point
   - Authority impersonation: +2 points
   - Typosquatting detected: +2 points
   - Sender domain mismatch: +1 point
4. Calculate total risk score
5. Map score to verdict:
   - 0-1 points: LEGITIMATE
   - 2-3 points: SUSPICIOUS
   - 4+ points: PHISHING
6. Generate human readable explanation

## Output Format
- verdict: PHISHING / SUSPICIOUS / LEGITIMATE
- risk_score: total points
- confidence: LOW / MEDIUM / HIGH
- explanation: 2-3 sentence summary for the user
- red_flags: list of specific signals that contributed to verdict
- tools_used: list of tools the agent called during this analysis

## Hard Rules
- Never produce a verdict with zero tools called
- Always include at least one red flag if verdict is PHISHING
- Always include tools_used so trajectory is visible to user
