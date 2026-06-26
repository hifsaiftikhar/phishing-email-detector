# Phishing Email Detection Agent

An AI agent that autonomously detects phishing emails using tool-calling,
trajectory evaluation, and multi-signal analysis.

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

## Architecture

```
User (Gmail or manual paste)
        ↓
Chrome Extension (ext/)
        ↓
Flask API (app.py)
        ↓
Security Screener (security/screener.py)
        ↓
Agent Loop (agent.py)
        ↓
Tool Selection by LLM (autonomous)
        ↓
Tools:
  - analyze_email_text
  - scan_email_urls (VirusTotal)
  - check_sender_domain (WHOIS)
  - generate_verdict
        ↓
Trajectory Logger → trajectory_logs/
        ↓
Verdict: PHISHING / SUSPICIOUS / LEGITIMATE
```

## Course Concepts Applied

| Day | Concept | Implementation |
|-----|---------|----------------|
| Day 1 | Agent loop, factory model | agent.py autonomous tool-calling loop |
| Day 1 | Harness design | AGENTS.md, security screener, trajectory logging |
| Day 2 | Tool integration | VirusTotal MCP-style tool, WHOIS domain checker |
| Day 3 | Agent Skills | skills/ folder with 4 SKILL.md files |
| Day 3 | Progressive disclosure | Skills load only when triggered |
| Day 4 | Security screening | Prompt injection detection before LLM call |
| Day 4 | Trajectory evaluation | Every agent step logged to trajectory_logs/ |
| Day 5 | Spec-driven development | Golden dataset + automated evaluator |

## Project Structure

```
phishing-email-detector/
  agent.py                    # Main agent loop with tool calling
  app.py                      # Flask API
  email_parser.py             # Email component extraction
  url_scanner.py              # VirusTotal integration
  prompt_engine.py            # Legacy LLM engine
  evaluate.py                 # Legacy evaluator
  AGENTS.md                   # Agent rules and harness design
  tools/
    domain_checker.py         # WHOIS domain reputation checker
  skills/
    email-analysis/SKILL.md   # Email text analysis skill
    url-scanning/SKILL.md     # URL scanning skill
    domain-reputation/SKILL.md # Domain reputation skill
    verdict-generation/SKILL.md # Verdict generation skill
  security/
    screener.py               # Prompt injection detection
  evaluation/
    golden_dataset.json       # 8 test cases with expected outputs
    evaluator.py              # Automated evaluation runner
  trajectory_logs/            # Agent reasoning traces
  ext/                        # Chrome extension
  Dockerfile                  # Docker deployment
```

## Agent Evaluation Results

Tested on original benchmark:

| Dataset | Accuracy | Precision | Recall | F1 |
|---------|----------|-----------|--------|-----|
| Nazario + Enron (100 emails) | 99% | 100% | 98% | 98.99% |
| Structured test set (127 emails) | 95.41% | 97.18% | 95.83% | 96.50% |

## Security Features

- Prompt injection detection before every LLM call
- All 10 prompt injection attempts correctly flagged as PHISHING
- Zero false positives on 30 legitimate transactional emails
- Social engineering detection without URLs

## Sample Trajectory Log

```json
{
  "timestamp": "2026-07-01T10:23:45",
  "verdict": {"verdict": "PHISHING", "risk_score": 5, "confidence": "HIGH"},
  "steps": [
    {"step": "security_screen", "result": {"safe": true}},
    {"step": "email_parse", "result": {"urls": ["http://paypa1.xyz/login"]}},
    {"step": "analyze_email_text", "output": {"risk_level": "HIGH", "red_flags": ["urgency"]}},
    {"step": "scan_email_urls", "output": {"verdict": "MALICIOUS", "malicious_count": 8}},
    {"step": "check_sender_domain", "output": {"typosquat_detected": true, "age_days": 3}},
    {"step": "generate_verdict", "output": {"verdict": "PHISHING", "risk_score": 5}}
  ],
  "total_steps": 6
}
```

## Live Demo

API deployed on Hugging Face:
https://hifsa65-phishing-email-detector.hf.space/health

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
| URL Scanner | VirusTotal API |
| Domain Checker | python-whois |
| Backend | Python, Flask |
| Frontend | Chrome Extension (Manifest V3) |
| Deployment | Docker, Hugging Face Spaces |

## Author

Hifsa Iftikhar
GitHub: @hifsaiftikhar
```
