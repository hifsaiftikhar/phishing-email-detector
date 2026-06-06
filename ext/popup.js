// popup.js
const SERVER_URL = "http://localhost:5000/analyze";

document.getElementById("analyzeBtn").addEventListener("click", analyzeEmail);

async function analyzeEmail() {
    const sender  = document.getElementById("sender").value.trim();
    const subject = document.getElementById("subject").value.trim();
    const body    = document.getElementById("body").value.trim();
    const btn     = document.getElementById("analyzeBtn");
    const result  = document.getElementById("result");

    if (!body) {
        showError("Please paste the email body before analyzing.");
        return;
    }

    btn.disabled    = true;
    btn.textContent = "Analyzing...";
    result.style.display = "block";
    result.innerHTML = `<div class="loading">⏳ Analyzing email with AI...</div>`;

    try {
        const response = await fetch(SERVER_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sender, subject, body }),
        });

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        const data = await response.json();
        showResult(data);

    } catch (error) {
        showError(
            "Could not connect to server.<br>" +
            "Make sure <b>app.py</b> is running in your terminal."
        );
    } finally {
        btn.disabled    = false;
        btn.textContent = "Analyze Email";
    }
}

function showResult(data) {
    const verdict     = data.verdict     || "UNKNOWN";
    const risk        = data.risk_score  || "Unknown";
    const explanation = data.explanation || "";
    const redFlags    = data.red_flags   || [];

    const isPhishing   = verdict === "PHISHING";
    const isLegitimate = verdict === "LEGITIMATE";

    const boxClass   = isPhishing ? "verdict-phishing" : isLegitimate ? "verdict-legitimate" : "verdict-unknown";
    const labelClass = isPhishing ? "phishing-color"   : isLegitimate ? "legitimate-color"   : "unknown-color";
    const icon       = isPhishing ? "🚨" : isLegitimate ? "✅" : "❓";

    let flagsHTML = "";
    if (redFlags.length > 0) {
        flagsHTML = `<div class="flags-title">Red Flags Detected:</div>`;
        redFlags.forEach(flag => {
            flagsHTML += `<div class="flag-item">⚠ ${flag}</div>`;
        });
    }

    document.getElementById("result").innerHTML = `
        <div class="verdict-box ${boxClass}">
            <div class="verdict-label ${labelClass}">${icon} ${verdict}</div>
            <div class="risk">Risk Level: ${risk}</div>
            <div class="explanation">${explanation}</div>
            ${flagsHTML}
        </div>
    `;
}

function showError(message) {
    document.getElementById("result").style.display = "block";
    document.getElementById("result").innerHTML =
        `<div class="error-box">❌ ${message}</div>`;
}