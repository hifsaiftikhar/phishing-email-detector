# Phishing Email Detection Agent

An AI agent that autonomously detects phishing emails using tool-calling,
progressive skill disclosure, trajectory evaluation, and multi-signal analysis.

Built as a capstone project for the Google x Kaggle 5-Day AI Agents
Intensive Vibe Coding Course.

## What Makes This an Agent (Not Just a Classifier)

Most phishing detectors make one LLM call and return a verdict.
This system is a proper tool-calling agent — the LLM autonomously
decides which tools to invoke based on what it discovers at each step.

Example agent reasoning:
- Reads email → finds suspicious URLs → calls url_scanner
- URL scan returns clean → notices new domain → calls domain_checker
- Domain is 3 days old → flags HIGH RISK → calls generate_verdict

The agent's path changes based on evidence. No fixed pipeline.

## Course Concepts Applied

| Day | Concept | Implementation |
|-----|---------|----------------|
| Day 1 | Agent loop, factory model | agent.py autonomous tool-calling loop |
| Day 1 | Harness design | AGENTS.md, security screener, trajectory logging |
| Day 2 | Tool integration | VirusTotal tool, WHOIS domain checker |
| Day 3 | Agent Skills | skills/ folder with 4 SKILL.md files |
| Day 3 | Progressive disclosure | L1 metadata loaded at startup, L2 body loaded on demand |
| Day 3 | Skills as source of truth | TOOLS list built dynamically from SKILL.md via skill_loader.py |
| Day 4 | Security screening | Prompt injection detection before every LLM call |
| Day 4 | Trajectory evaluation | Every agent step logged to trajectory_logs/ |
| Day 5 | Spec-driven development | Golden dataset + automated evaluator |

## Architecture

```
User Email Input
      ↓
Security Screener (security/screener.py)
      ↓ blocks prompt injection
Agent Loop (agent.py)
      ↓
Skill Loader (tools/skill_loader.py)
  L1: loads skill metadata at startup from SKILL.md files
  L2: loads full skill body when tool is triggered
      ↓
LLM decides which tools to call autonomously
      ↓
Tools:
  - analyze_email_text  ← skills/email-analysis/SKILL.md
  - scan_email_urls     ← skills/url-scanning/SKILL.md
  - check_sender_domain ← skills/domain-reputation/SKILL.md
  - generate_verdict    ← skills/verdict-generation/SKILL.md
      ↓
Trajectory Logger → trajectory_logs/
      ↓
Verdict: PHISHING / SUSPICIOUS / LEGITIMATE
```

## Project Structure

```
phishing-email-detector/
  agent.py                      # Main agent loop with tool calling
  app.py                        # Flask API
  email_parser.py               # Email component extraction
  url_scanner.py                # VirusTotal integration
  AGENTS.md                     # Agent rules and harness design
  tools/
    skill_loader.py             # Progressive disclosure L1/L2 loader
    domain_checker.py           # WHOIS domain reputation checker
  skills/
    email-analysis/SKILL.md     # Trigger + runbook for text analysis
    url-scanning/SKILL.md       # Trigger + runbook for URL scanning
    domain-reputation/SKILL.md  # Trigger + runbook for domain checks
    verdict-generation/SKILL.md # Trigger + runbook for verdict
  security/
    screener.py                 # Prompt injection detection
  evaluation/
    golden_dataset.json         # 8 test cases with expected outputs
    evaluator.py                # Automated evaluation runner
  trajectory_logs/              # Real agent reasoning traces
  ext/                          # Chrome extension
```

## Progressive Disclosure — How Skills Actually Work

Skills are not just documentation. They are the source of truth for tool definitions.

At startup, `skill_loader.py` reads each `SKILL.md` and extracts:
- Skill name
- Trigger description → becomes the tool description the LLM sees

When a tool is called, the full `SKILL.md` body loads into context (L2).
This means the agent only pays token cost for skills it actually uses.

```python
# L1: Build TOOLS list from SKILL.md files at startup
TOOLS = build_tools_from_skills()

# L2: Load full skill body when tool is triggered
skill_context = get_skill_context_for_tool(tool_name)
```

## Real Trajectory Logs

Three confirmed trajectory logs in `trajectory_logs/`:

**Phishing email** — 6 steps, PHISHING verdict
- security_screen → email_parse → analyze_email_text → scan_email_urls → check_sender_domain → generate_verdict
- URL flagged by 12 malicious engines, typosquatting detected on paypa1.com

**Legitimate email** — 5 steps, LEGITIMATE verdict
- Agent skipped URL scanning (no URLs found)
- Recognized github.com as known legitimate domain

**Prompt injection** — 2 steps, PHISHING verdict
- Security screener caught injection before LLM call
- Agent bypassed entirely, immediate PHISHING verdict

## Evaluation Results

| Dataset | Accuracy | Precision | Recall | F1 |
|---------|----------|-----------|--------|-----|
| Nazario + Enron (100 emails) | 99% | 100% | 98% | 98.99% |
| Structured test set (127 emails) | 95.41% | 97.18% | 95.83% | 96.50% |

## Setup

```bash
git clone https://github.com/hifsaiftikhar/phishing-email-detector.git
cd phishing-email-detector
pip install flask flask-cors groq requests python-dotenv python-whois
```

Create `.env`:
```
GROQ_API_KEY=your_groq_api_key
VT_API_KEY=your_virustotal_api_key
```

Run:
```bash
python app.py
```

Run evaluation:
```bash
python evaluation/evaluator.py
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| Agent Framework | Custom tool-calling loop with Groq |
| AI Model | Llama 3.3 70B via Groq API |
| Skill System | Progressive disclosure via skill_loader.py |
| URL Scanner | VirusTotal API |
| Domain Checker | python-whois |
| Security | Custom prompt injection screener |
| Backend | Python, Flask |
| Frontend | Chrome Extension (Manifest V3) |

## Author

Hifsa Iftikhar
GitHub: @hifsaiftikhar
HuggingFace: Hifsa65
LinkedIn: linkedin.com/in/hifsa-iftikhar