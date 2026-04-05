import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_phish_shield():
    model = DeepRiskModel()
    
    test_cases = [
        "https://google.com",
        "http://1.2.3.4/login",
        "https://paypal-support-verify-amazon-winner.xyz"
    ]
    
    print("Running PhishShield Verification Tests...")
    
    for url in test_cases:
        print(f"\nAnalyzing: {url}")
        report = model.analyze_url_phish_shield(url)
        print(json.dumps(report, indent=2))
        
        # Quick validation
        if "google.com" in url:
            assert report["classification"] == "SAFE WEBSITE"
        if "1.2.3.4" in url:
            assert report["risk_score"] >= 30 # IP host is +30
        if "winner" in url:
            assert report["classification"] == "HIGH RISK WEBSITE"

    print("\nALL VERIFICATION TESTS PASSED (PhishShield logic).")

if __name__ == "__main__":
    test_phish_shield()
