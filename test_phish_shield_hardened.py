import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_hardened_phish_shield_ai():
    model = DeepRiskModel()
    
    print("Testing Hardened PhishShield AI (Trust List + Entropy + Fuzzy)...")
    
    test_cases = {
        "https://accounts.google.com/login": "LOW RISK", # Trusted root (Trust List)
        "http://paypa1-secure-verify.com": "HIGH RISK", # Typosquatting (Fuzzy match)
        "https://a1b2c3d4e5f6g7h8.xyz/auth": "HIGH RISK", # DGA (Entropy > 4.2)
        "https://microsoft.com/en-us/": "LOW RISK", # Trusted root
        "http://amazon-prime-reward.support-help.online": "HIGH RISK" # Brand mismatch + High-risk TLD
    }
    
    for url, expected in test_cases.items():
        print(f"\nAnalyzing: {url}")
        report = model.analyze_url_phish_shield_ai(url)
        print(f"Result: {report['classification']} (Score: {report['risk_score']}%)")
        print(f"Reasons: {report['reasons']}")
        
        # Verify calibrated results
        assert report["classification"] == expected
        if expected == "LOW RISK":
            assert report["risk_score"] <= 24
        if expected == "HIGH RISK":
            assert report["risk_score"] >= 60

    print("\nALL HARDENING VERIFICATION TESTS PASSED.")

if __name__ == "__main__":
    test_hardened_phish_shield_ai()
