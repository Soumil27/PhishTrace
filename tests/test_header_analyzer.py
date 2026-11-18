import json
import sys
from pathlib import Path

# Add the PhishTrace project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.header_analyzer import analyze_headers

report_path = PROJECT_ROOT / "reports" / "sample_analysis.json"
data = json.loads(report_path.read_text(encoding="utf-8-sig"))

result = analyze_headers(data)
print(json.dumps(result, indent=2))

