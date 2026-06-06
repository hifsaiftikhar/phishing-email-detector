"""
FLASK BACKEND
=============
Run: python app.py
Server runs at: http://localhost:5000
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from email_parser import parse_email
from prompt_engine import analyze_email
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

API_KEY    = os.getenv("GROQ_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    sender  = data.get("sender",  "")
    subject = data.get("subject", "")
    body    = data.get("body",    "")

    if not body:
        return jsonify({"error": "Email body is empty"}), 400

    parsed = parse_email(sender, subject, body)
    result = analyze_email(parsed, api_key=API_KEY, vt_api_key=VT_API_KEY)

    return jsonify(result)


if __name__ == "__main__":
    print("="*45)
    print("  Phishing Detector Server Running")
    print("  URL: http://localhost:5000")
    print("  Press CTRL+C to stop")
    print("="*45)
    app.run(debug=True, port=5000)