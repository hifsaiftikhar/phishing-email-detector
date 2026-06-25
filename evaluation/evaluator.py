"""
Agent Evaluator
Runs the phishing detection agent against the golden dataset
and reports accuracy, per-category results, and trajectory stats.
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import run_agent


def load_golden_dataset(path: str = "evaluation/golden_dataset.json") -> dict:
    with open(path, "r") as f:
        return json.load(f)


def run_evaluation():
    """Run agent against all golden dataset cases."""
    
    dataset = load_golden_dataset()
    cases = dataset["cases"]
    
    results = []
    correct = 0
    total = len(cases)
    
    print(f"\nRunning evaluation on {total} test cases...\n")
    print("-" * 60)
    
    for case in cases:
        case_id = case["id"]
        category = case["category"]
        expected = case["expected_verdict"]
        
        # Build email text
        sender = case["input"]["sender"]
        subject = case["input"]["subject"]
        body = case["input"]["body"]
        email_text = f"From: {sender}\nSubject: {subject}\n\n{body}"
        
        print(f"Testing {case_id} ({category})...")
        
        try:
            result = run_agent(email_text)
            verdict = result["verdict"]
            actual = verdict.get("verdict", "SUSPICIOUS")
            trajectory = result["trajectory"]
            
            passed = actual == expected
            if passed:
                correct += 1
            
            results.append({
                "id": case_id,
                "category": category,
                "expected": expected,
                "actual": actual,
                "passed": passed,
                "steps_taken": len(trajectory),
                "tools_used": [t["step"] for t in trajectory]
            })
            
            status = "PASS" if passed else "FAIL"
            print(f"  {status} - Expected: {expected}, Got: {actual}, Steps: {len(trajectory)}")
            
        except Exception as e:
            print(f"  ERROR - {str(e)}")
            results.append({
                "id": case_id,
                "category": category,
                "expected": expected,
                "actual": "ERROR",
                "passed": False,
                "error": str(e)
            })
    
    print("-" * 60)
    accuracy = (correct / total) * 100
    print(f"\nResults: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
    
    # Category breakdown
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"correct": 0, "total": 0}
        categories[cat]["total"] += 1
        if r["passed"]:
            categories[cat]["correct"] += 1
    
    print("\nBy category:")
    for cat, stats in categories.items():
        cat_accuracy = (stats["correct"] / stats["total"]) * 100
        print(f"  {cat}: {stats['correct']}/{stats['total']} ({cat_accuracy:.0f}%)")
    
    # Save results
    report = {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "results": results,
        "category_breakdown": categories
    }
    
    os.makedirs("evaluation", exist_ok=True)
    with open("evaluation/eval_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nFull report saved to evaluation/eval_report.json")
    return report


if __name__ == "__main__":
    run_evaluation()
