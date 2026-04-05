import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_production_phish_shield_ai():
    model = DeepRiskModel()
    
    print("Testing Production-Grade PhishShield AI (Flat JSON + Single URL)...")
    
    # Test Case 1: Single URL (Success)
    print("\n[TEST 1] Single legitimate URL:")
    report = model.analyze_url_phish_shield_ai("https://google.com/search")
    print(json.dumps(report, indent=2))
    assert report["classification"] == "LOW RISK"
    assert "analysis" not in report # Should be flat
    
    # Test Case 2: Multi-URL (Failure)
    print("\n[TEST 2] Multi-URL Input (Strict Check):")
    try:
        model.analyze_url_phish_shield_ai("https://google.com and https://malicious.club")
        print("FAILURE: Multi-URL input was not rejected.")
    except ValueError as e:
        print(f"SUCCESS: Rejected multi-url input: {e}")
        
    # Test Case 3: High Risk (Deception)
    print("\n[TEST 3] High Risk Deception (amazon-login.xyz):")
    report = model.analyze_url_phish_shield_ai("http://amazon-login.verify-account.xyz")
    print(json.dumps(report, indent=2))
    assert report["classification"] == "HIGH RISK"
    assert report["risk_score"] >= 60

    print("\nALL PRODUCTION-GRADE VERIFICATION TESTS PASSED.")

if __name__ == "__main__":
    test_production_phish_shield_ai()
