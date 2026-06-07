"""
EVALUATION SCRIPT
=================
Runs all emails from real_email_dataset.csv through the system.
Compares AI verdict vs true label.
Calculates: Accuracy, Precision, Recall, F1 Score.

Run:
  python evaluate.py

Output:
  - Prints results to terminal
  - Saves detailed results to evaluation_results.csv
"""

import pandas as pd
import time
import sys
from email_parser import parse_email
from prompt_engine import analyze_email

# ─────────────────────────────────────────────
# PASTE YOUR GROQ API KEY HERE
# ─────────────────────────────────────────────
import os
from dotenv import load_dotenv
load_dotenv()
API_KEY = os.getenv("GROQ_API_KEY")


def run_evaluation():

    # Load dataset
    print("Loading dataset...")
    df = pd.read_csv("structured_test_dataset.csv")
    total = len(df)
    print(f"Total emails to evaluate: {total}\n")

    results = []
    correct = 0

    for i, row in df.iterrows():

        true_label = row["label"].upper()  # PHISHING or LEGITIMATE
        sender     = row["sender"]
        subject    = row["subject"]
        body       = row["body"]

        print(f"[{i+1}/{total}] Subject: {str(subject)[:50]}...")

        try:
            # Step 1: Parse email
            parsed = parse_email(sender, subject, body)

            # Step 2: Get AI verdict
            result = analyze_email(parsed, api_key=API_KEY)

            ai_verdict = result.get("verdict", "UNKNOWN").upper()
            risk_score = result.get("risk_score", "Unknown")
            explanation= result.get("explanation", "")

            # Check if correct
            is_correct = (ai_verdict == true_label)
            if is_correct:
                correct += 1

            print(f"         True: {true_label} | AI: {ai_verdict} | {'✅' if is_correct else '❌'}")

            results.append({
                "id":          row["id"],
                "sender":      sender,
                "subject":     subject,
                "true_label":  true_label,
                "ai_verdict":  ai_verdict,
                "risk_score":  risk_score,
                "explanation": explanation,
                "correct":     is_correct,
            })

        except Exception as e:
            print(f"         ERROR: {e}")
            results.append({
                "id":          row["id"],
                "sender":      sender,
                "subject":     subject,
                "true_label":  true_label,
                "ai_verdict":  "ERROR",
                "risk_score":  "Unknown",
                "explanation": str(e),
                "correct":     False,
            })

        # Pause to avoid hitting Groq rate limit
        time.sleep(1.5)

    # ─────────────────────────────────────────
    # CALCULATE METRICS
    # ─────────────────────────────────────────

    results_df = pd.DataFrame(results)

    # Filter out errors for metric calculation
    valid = results_df[results_df["ai_verdict"] != "ERROR"]

    # True Positives, False Positives, True Negatives, False Negatives
    TP = len(valid[(valid["true_label"] == "PHISHING")   & (valid["ai_verdict"] == "PHISHING")])
    TN = len(valid[(valid["true_label"] == "LEGITIMATE") & (valid["ai_verdict"] == "LEGITIMATE")])
    FP = len(valid[(valid["true_label"] == "LEGITIMATE") & (valid["ai_verdict"] == "PHISHING")])
    FN = len(valid[(valid["true_label"] == "PHISHING")   & (valid["ai_verdict"] == "LEGITIMATE")])

    accuracy  = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    # ─────────────────────────────────────────
    # PRINT RESULTS
    # ─────────────────────────────────────────

    print("\n" + "="*50)
    print("           EVALUATION RESULTS")
    print("="*50)
    print(f"Total Emails Tested : {total}")
    print(f"Correct Predictions : {correct}")
    print(f"Errors              : {len(results_df[results_df['ai_verdict'] == 'ERROR'])}")
    print("-"*50)
    print(f"True Positives  (TP): {TP}")
    print(f"True Negatives  (TN): {TN}")
    print(f"False Positives (FP): {FP}")
    print(f"False Negatives (FN): {FN}")
    print("-"*50)
    print(f"Accuracy  : {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"Precision : {precision:.4f}  ({precision*100:.2f}%)")
    print(f"Recall    : {recall:.4f}  ({recall*100:.2f}%)")
    print(f"F1 Score  : {f1:.4f}  ({f1*100:.2f}%)")
    print("="*50)

    # Save detailed results
    results_df.to_csv("evaluation_results.csv", index=False)
    print(f"\nDetailed results saved to: evaluation_results.csv")


if __name__ == "__main__":
    if API_KEY == "paste_your_groq_key_here":
        print("ERROR: Paste your Groq API key in the API_KEY variable.")
        sys.exit(1)

    run_evaluation()