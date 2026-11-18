import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.ioc_extractor import extract_iocs

sample_file = PROJECT_ROOT / "samples" / "suspicious" / "sample_phishing.eml"
result = extract_iocs(sample_file)

print(json.dumps(result, indent=2))
