import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.authentication import analyze_authentication

report_path = PROJECT_ROOT / "reports" / "sample_analysis.json"
email_data = json.loads(report_path.read_text(encoding="utf-8-sig"))

result = analyze_authentication(email_data)
print(json.dumps(result, indent=2))
