// content.js
// Injects a floating "Analyze" button inside Gmail

function injectButton() {
    // Don't inject twice
    if (document.getElementById("phish-btn")) return;

    const btn = document.createElement("div");
    btn.id = "phish-btn";
    btn.innerHTML = "🔍 Check Email";
    btn.style.cssText = `
        position: fixed;
        bottom: 30px;
        right: 30px;
        background: #c0392b;
        color: white;
        padding: 12px 18px;
        border-radius: 25px;
        font-size: 14px;
        font-weight: bold;
        cursor: pointer;
        z-index: 99999;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        font-family: Arial, sans-serif;
    `;

    btn.addEventListener("click", () => {
        // Get subject
        let subject = "";
        const subjectEl = document.querySelector("h2.hP");
        if (subjectEl) subject = subjectEl.innerText.trim();

        // Get sender
        let sender = "";
        const senderEl = document.querySelector(".gD");
        if (senderEl) {
            sender = senderEl.getAttribute("email") || senderEl.innerText.trim();
        }

        // Get body
        let body = "";
        const bodyEl = document.querySelector(".a3s.aiL") ||
                       document.querySelector(".a3s");
        if (bodyEl) body = bodyEl.innerText.trim();

        if (!subject && !body) {
            alert("Please open an email first.");
            return;
        }

        // Send to Flask and show result
        btn.innerHTML = "⏳ Analyzing...";

        fetch("https://hifsa65-phishing-email-detector.hf.space/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender:  sender  || "unknown",
                subject: subject || "(no subject)",
                body:    body.substring(0, 3000)
            })
        })
        .then(r => r.json())
        .then(data => {
            const verdict = data.verdict || "UNKNOWN";
            const risk    = data.risk_score || "";
            const explanation = data.explanation || "";
            const flags   = (data.red_flags || []).join("\n• ");

            const color = verdict === "PHISHING" ? "#c0392b" : "#27ae60";
            const icon  = verdict === "PHISHING" ? "🚨" : "✅";

            // Show result popup
            showResult(verdict, risk, explanation, flags, color, icon);
            btn.innerHTML = "🔍 Check Email";
        })
        .catch(() => {
            alert("Could not connect. Make sure app.py is running.");
            btn.innerHTML = "🔍 Check Email";
        });
    });

    document.body.appendChild(btn);
}

function showResult(verdict, risk, explanation, flags, color, icon) {
    // Remove old result if exists
    const old = document.getElementById("phish-result");
    if (old) old.remove();

    const div = document.createElement("div");
    div.id = "phish-result";
    div.style.cssText = `
        position: fixed;
        bottom: 90px;
        right: 30px;
        background: #1a1a1a;
        color: white;
        padding: 16px;
        border-radius: 12px;
        font-size: 13px;
        z-index: 99999;
        max-width: 320px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        border: 2px solid ${color};
        font-family: Arial, sans-serif;
        line-height: 1.5;
    `;

    div.innerHTML = `
        <div style="font-size:18px;font-weight:bold;color:${color};margin-bottom:6px">
            ${icon} ${verdict}
        </div>
        <div style="color:#aaa;font-size:11px;margin-bottom:8px">Risk: ${risk}</div>
        <div style="color:#ddd;margin-bottom:8px">${explanation}</div>
        ${flags ? `<div style="color:#e74c3c;font-size:11px">• ${flags}</div>` : ""}
        <div style="text-align:right;margin-top:10px">
            <span id="phish-close" style="cursor:pointer;color:#888;font-size:12px">✕ Close</span>
        </div>
    `;

    document.body.appendChild(div);
    document.getElementById("phish-close").addEventListener("click", () => div.remove());
}

// Inject button when Gmail loads an email
// Watch for URL changes (Gmail is a single page app)
let lastUrl = location.href;
new MutationObserver(() => {
    if (location.href !== lastUrl) {
        lastUrl = location.href;
        setTimeout(injectButton, 1500);
    }
}).observe(document, { subtree: true, childList: true });

// Initial injection
setTimeout(injectButton, 2000);