import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_strict_validator_ai():
    model = DeepRiskModel()
    
    print("Testing Strict Validator PhishShield AI (Bare Domains + Sanitization)...")
    
    test_cases = [
        ("google.com", "LOW RISK", True), # Bare domain support
        ("https://paypal.com/login", "LOW RISK", True), # Normal URL
        ("paypa1.com", "HIGH RISK", True), # Bare domain typosquat
        ("Hello this is random text", "INVALID INPUT", False), # Random text
        ("http://google.com http://malicious.com", "INVALID INPUT", False), # Multi-URL
        (" ", "INVALID INPUT", False), # Empty
    ]
    
    for input_text, expected_class, expected_valid in test_cases:
        print(f"\nAnalyzing: '{input_text}'")
        report = model.analyze_url_phish_shield_ai(input_text)
        print(f"Result: {report['classification']} (Valid: {report['valid']})")
        print(f"Score: {report['risk_score']} | Confidence: {report['confidence']}")
        print(f"Reasons: {report['reasons']}")
        
        # Verify calibrated results
        assert report["classification"] == expected_class
        assert report["valid"] == expected_valid
        
        if not expected_valid:
            assert report["risk_score"] is None
            assert report["confidence"] == "LOW"
        else:
            assert isinstance(report["risk_score"], int)
            assert report["normalized_url"].startswith("http")

    print("\nALL STRICT VALIDATOR VERIFICATION TESTS PASSED.")

if __name__ == "__main__":
    test_strict_validator_ai()
