import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from phishtrace import investigate

DATASET = [
    ("samples/benign/sample_benign.eml", "benign"),
    ("samples/suspicious/sample_phishing.eml", "phishing"),
    ("samples/suspicious/sample_urgent_phishing.eml", "phishing"),
    ("samples/benign/meeting_reminder.eml", "benign"),
    ("samples/benign/password_policy.eml", "benign"),
    ("samples/suspicious/invoice_phishing.eml", "phishing"),
    ("samples/suspicious/account_alert.eml", "phishing"),
]

results = []

for relative_path, expected in DATASET:
    path = ROOT / relative_path

    if not path.exists():
        print(f"SKIPPED: {relative_path}")
        continue

    try:
        report = investigate(path)
        assessment = report.get("overall_assessment", {})
        verdict = str(assessment.get("verdict", ""))
        reasons = assessment.get("risk_reasons", [])
        score = assessment.get("risk_score", 0)
        level = assessment.get("risk_level", "Unknown")

        # Preserve the application's actual verdict.
        # "Suspicious" means flagged for investigation, not confirmed phishing.
        if verdict.lower().startswith("suspicious"):
            predicted = "flagged"
        elif verdict.lower().startswith("no configured indicators"):
            predicted = "not_flagged"
        else:
            predicted = "inconclusive"

        # A flagged benign sample is a potential false positive.
        # A suspicious sample not flagged is a potential false negative.
        if expected == "benign" and predicted == "flagged":
            outcome = "POTENTIAL_FALSE_POSITIVE"
        elif expected == "phishing" and predicted == "not_flagged":
            outcome = "POTENTIAL_FALSE_NEGATIVE"
        elif predicted == "inconclusive":
            outcome = "INCONCLUSIVE"
        elif expected == "phishing" and predicted == "flagged":
            outcome = "FLAGGED_EXPECTED_PHISHING"
        else:
            outcome = "BENIGN_NOT_FLAGGED"

        results.append({
            "file": relative_path,
            "expected": expected,
            "predicted": predicted,
            "verdict": verdict,
            "risk_score": score,
            "risk_level": level,
            "risk_reasons": reasons,
            "outcome": outcome,
        })

    except Exception as exc:
        results.append({
            "file": relative_path,
            "expected": expected,
            "predicted": "error",
            "outcome": "ERROR",
            "error": str(exc),
        })

summary = {
    "samples_tested": len(results),
    "flagged_expected_phishing": sum(
        r["outcome"] == "FLAGGED_EXPECTED_PHISHING" for r in results
    ),
    "benign_not_flagged": sum(
        r["outcome"] == "BENIGN_NOT_FLAGGED" for r in results
    ),
    "potential_false_positives": sum(
        r["outcome"] == "POTENTIAL_FALSE_POSITIVE" for r in results
    ),
    "potential_false_negatives": sum(
        r["outcome"] == "POTENTIAL_FALSE_NEGATIVE" for r in results
    ),
    "inconclusive": sum(r["outcome"] == "INCONCLUSIVE" for r in results),
    "errors": sum(r["outcome"] == "ERROR" for r in results),
    "note": (
        "Preliminary evaluation using synthetic samples. "
        "A suspicious verdict means further investigation is recommended, "
        "not that phishing has been conclusively established. "
        "Metrics should not be treated as real-world performance estimates."
    ),
}

output = {
    "summary": summary,
    "results": results,
}

out = ROOT / "reports" / "sample_evaluation.json"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(output, indent=2), encoding="utf-8")

print("\n=== PhishTrace Evaluation ===")
for r in results:
    print(
        f"{r['file']}: expected={r['expected']}, "
        f"verdict={r.get('verdict', 'ERROR')}, "
        f"score={r.get('risk_score', 'N/A')}, "
        f"level={r.get('risk_level', 'N/A')}, "
        f"result={r['outcome']}"
    )

print("\n=== Summary ===")
for key, value in summary.items():
    print(f"{key}: {value}")

print(f"\nSaved: {out}")
