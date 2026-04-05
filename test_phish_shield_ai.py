import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_phish_shield_ai():
    model = DeepRiskModel()
    
    test_cases = [
        "https://google.com/login", # Should be LOW RISK (trusted root)
        "http://paypal.verify-secure-billing.xyz", # Should be HIGH RISK (deception + brand + http)
        "https://bit.ly/claim-prize" # Should be MEDIUM/HIGH RISK (shortener + lure)
    ]
    
    print("Running PhishShield AI Holistic Verification Tests...")
    
    for url in test_cases:
        print(f"\nAnalyzing: {url}")
        report = model.analyze_url_phish_shield_ai(url)
        print(json.dumps(report, indent=2))
        
        # Validate structure
        assert "analysis" in report
        assert "root_domain" in report["analysis"]
        assert "classification" in report
        
        if "google.com" in url:
            assert report["classification"] == "LOW RISK"
        if "paypal" in url:
            assert report["classification"] == "HIGH RISK"

    print("\nALL PHISHSHIELD AI VERIFICATION TESTS PASSED.")

if __name__ == "__main__":
    test_phish_shield_ai()
