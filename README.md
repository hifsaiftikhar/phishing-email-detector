# Phishing Email Detector

A Chrome extension that detects phishing emails using a Large Language Model (LLM) and VirusTotal URL scanning.

## Overview

This project combines AI-powered email analysis with real-time URL scanning to identify phishing emails. Users can paste email content into the Chrome extension or use the floating button directly inside Gmail to get an instant verdict.

## Features

- AI-powered phishing detection using Groq (Llama 3.3 70B)
- Real-time URL scanning via VirusTotal (70+ antivirus engines)
- Chrome extension with clean popup UI
- Floating Check Email button inside Gmail
- 99% accuracy on 100 real emails from Nazario and Enron datasets
- Returns verdict, risk score, explanation, and red flags

## System Architecture

```
User (Gmail or manual paste)
        ↓
Chrome Extension (ext/)
        ↓
Flask Backend (app.py)
        ↓
Email Parser → LLM (Groq API) + URL Scanner (VirusTotal)
        ↓
Verdict: PHISHING or LEGITIMATE
```

## Project Structure

```
phishing-email-detector/
    app.py               # Flask backend server
    email_parser.py      # Extracts sender, subject, body, URLs, signals
    prompt_engine.py     # Sends email to Groq AI, returns verdict
    url_scanner.py       # Checks URLs against VirusTotal
    evaluate.py          # Runs evaluation on dataset, calculates metrics
    ext/
        manifest.json    # Chrome extension config
        popup.html       # Extension UI
        popup.js         # Extension logic
        content.js       # Gmail floating button
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| AI Model | Llama 3.3 70B via Groq API |
| URL Scanner | VirusTotal API |
| Frontend | HTML, CSS, JavaScript |
| Browser | Chrome Extension (Manifest V3) |

## Evaluation Results

Tested on 100 real emails (50 phishing from Nazario corpus + 50 legitimate from Enron dataset).

| Metric | Score |
|--------|-------|
| Accuracy | 99.00% |
| Precision | 100.00% |
| Recall | 98.00% |
| F1 Score | 98.99% |

## Setup Instructions

### 1. Clone the repository

```
git clone https://github.com/hifsaiftikhar/phishing-email-detector.git
cd phishing-email-detector
```

### 2. Install dependencies

```
pip install flask flask-cors groq requests python-dotenv
```

### 3. Create a .env file

Create a file called `.env` in the project folder:

```
GROQ_API_KEY=your_groq_api_key_here
VT_API_KEY=your_virustotal_api_key_here
```

Get your free Groq API key at: https://console.groq.com
Get your free VirusTotal API key at: https://www.virustotal.com

### 4. Run the Flask server

```
python app.py
```

Server runs at http://localhost:5000

### 5. Load the Chrome extension

- Open Chrome and go to `chrome://extensions`
- Enable Developer Mode (top right toggle)
- Click Load unpacked
- Select the `ext` folder

### 6. Use the extension

**Option A — Manual:**
Click the extension icon, paste sender, subject and body, click Analyze Email.

**Option B — Gmail:**
Open any email in Gmail. Click the red Check Email button at the bottom right of the page.

## Dataset

- **Phishing emails:** Nazario Phishing Corpus
- **Legitimate emails:** Enron Email Dataset
- **Synthetic emails:** 30 manually created emails for development

## Author

Hifsa Iftikhar
BS Artificial Intelligence — University of Management and Technology (UMT), Lahore
