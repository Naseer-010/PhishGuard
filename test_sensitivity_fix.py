import sys
import os
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel

def test_sensitivity():
    model = DeepRiskModel()
    
    # Simulate a suspicious set of features
    # 1. No HTTPS (is_https=0) -> +25
    # 2. Host is IP (host_is_ip=1) -> +40
    # 3. Recent Domain (domain_recent=1) -> +30
    # Total infrastructure score: 95 (Dangerous / Red)
    
    print("Testing suspicious infrastructure...")
    # We can't easily mock the live feature extractor without complex patching,
    # but we can look at the _infrastructure_heuristic_score directly.
    
    suspicious_features = {
        "is_https": 0,
        "whois_available": 0,
        "domain_recent": 1,
        "host_is_ip": 1,
        "uses_ip_host": 1,
        "has_punycode": 0,
        "suspicious_tld": 1,
        "dns_resolves": 1,
        "resolved_ip_count": 1,
        "non_standard_port": 0,
        "tls_checked": 1,
        "tls_valid": 0,
        "tls_expiring_soon": 0
    }
    
    score = model._infrastructure_heuristic_score(suspicious_features)
    print(f"Infrastructure Heuristic Score for suspicious site: {score}")
    
    verdict = model._verdict(score)
    print(f"Verdict for score {score}: {verdict}")
    
    # Assertions
    if score >= 75:
        print("SUCCESS: Suspicious site correctly hits Red threshold (>75)")
    else:
        print(f"FAILURE: Score {score} is too low for a highly suspicious site")

if __name__ == "__main__":
    test_sensitivity()
