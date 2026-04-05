import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_neural_criteria_ai():
    model = DeepRiskModel()
    
    print("Testing Neural Criteria PhishShield AI (7 Forensic Dimensions)...")
    
    test_cases = {
        "https://google.com/search": "LOW RISK", # Trusted root
        "https://random-unknown-blog-123.net": "MEDIUM RISK", # Unfamiliar but structurally normal
        "http://verify-bank-chase.com.security-login.xyz": "HIGH RISK" # Structural + Impersonation + TLD
    }
    
    for url, expected in test_cases.items():
        print(f"\nAnalyzing: {url}")
        report = model.analyze_url_phish_shield_ai(url)
        print(f"Result: {report['classification']} (Score: {report['risk_score']}%)")
        print(f"Criteria Match: {json.dumps(report['criteria_match'], indent=2)}")
        
        # Verify calibrated results
        assert report["classification"] == expected
        assert "criteria_match" in report
        assert len(report["criteria_match"]) == 7
        
        if "google.com" in url:
            assert report["criteria_match"]["root_domain_trust"] == "LOW concern"
        if "security-login.xyz" in url:
            assert report["criteria_match"]["structural_deception"] == "HIGH concern"

    print("\nALL NEURAL CRITERIA VERIFICATION TESTS PASSED.")

if __name__ == "__main__":
    test_neural_criteria_ai()
