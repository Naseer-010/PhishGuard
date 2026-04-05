import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def debug_hardened_scores():
    model = DeepRiskModel()
    
    test_urls = [
        "http://paypa1-secure-verify.com",
        "https://a1b2c3d4e5f6g7h8.xyz/auth"
    ]
    
    for url in test_urls:
        print(f"\n--- Debugging: {url} ---")
        report = model.analyze_url_phish_shield_ai(url)
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    debug_hardened_scores()
