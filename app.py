"""
Phishing Email Detector - Flask API
Now powered by a tool-calling agent that autonomously decides
which tools to invoke based on what it discovers.
"""

import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from agent import run_agent

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "2.0-agent"})


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main endpoint. Accepts email content and returns agent verdict.
    The agent autonomously decides which tools to call.
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Build email text from components
        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")
        
        if not body:
            return jsonify({"error": "Email body is required"}), 400
        
        email_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
        
        # Run the agent
        result = run_agent(email_text)
        
        verdict = result.get("verdict", {})
        trajectory = result.get("trajectory", [])
        
        return jsonify({
            "verdict": verdict.get("verdict", "SUSPICIOUS"),
            "risk_score": verdict.get("risk_score", 0),
            "confidence": verdict.get("confidence", "MEDIUM"),
            "explanation": verdict.get("explanation", ""),
            "red_flags": verdict.get("findings", []),
            "tools_used": verdict.get("tools_used", []),
            "agent_steps": len(trajectory)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/trajectory/<filename>", methods=["GET"])
def get_trajectory(filename):
    """
    Returns a specific trajectory log file.
    Useful for debugging and demonstrating agent reasoning.
    """
    try:
        filepath = f"trajectory_logs/{filename}"
        if not os.path.exists(filepath):
            return jsonify({"error": "Trajectory not found"}), 404
            
        with open(filepath, "r") as f:
            data = json.load(f)
        return jsonify(data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/trajectories", methods=["GET"])
def list_trajectories():
    """Lists all saved trajectory logs."""
    try:
        if not os.path.exists("trajectory_logs"):
            return jsonify({"trajectories": []})
            
        files = os.listdir("trajectory_logs")
        json_files = [f for f in files if f.endswith(".json")]
        json_files.sort(reverse=True)
        
        return jsonify({
            "trajectories": json_files,
            "count": len(json_files)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    app.run(host="0.0.0.0", port=port, debug=False)
