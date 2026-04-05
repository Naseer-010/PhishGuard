import json
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_ultimate_hybrid_fusion():
    model = DeepRiskModel()
    
    test_cases = [
        "https://google.com/login", # Should be LOW RISK (Positive features + Trusted root)
        "http://amazon-support.account-verify-login.xyz", # Should be HIGH RISK (Bad features + Brand Impersonation)
        "https://bit.ly/secure-access" # Should be MEDIUM/HIGH RISK (Shortener + Keyword)
    ]
    
    print("Testing Ultimate Hybrid PhishShield Cyber AI Fusion...")
    
    for url in test_cases:
        print(f"\nAnalyzing: {url}")
        report = model.analyze_url_phish_shield_ai(url)
        
        # Verify Fused Results
        print(f"Risk Score: {report['risk_score']}%")
        print(f"Classification: {report['classification']}")
        print(f"Confidence: {report['confidence']}")
        print("Analysis Summary:", report['summary'])
        
        # Structure Check
        assert "analysis" in report
        assert "root_domain_trust" in report["analysis"]
        assert "endpoint_intent" in report["analysis"]
        assert len(report["reasons"]) > 0

    print("\nALL HYBRID FUSION TESTS PASSED.")

if __name__ == "__main__":
    test_ultimate_hybrid_fusion()
