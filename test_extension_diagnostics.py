import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from models.deep_risk_model.model import DeepRiskModel

def test_extension_compliance():
    model = DeepRiskModel()
    
    test_cases = [
        # Rule 1: Scam Bait -> HIGH/BLOCK
        {
            "url": "http://claim-free-reward.top", 
            "expected_classification": "HIGH RISK",
            "expected_action": "BLOCK",
            "desc": "Rule 1: Scam Bait on untrusted domain"
        },
        # Rule 2: Financial -> MEDIUM/HIGH
        {
            "url": "http://verify-bank-update.net", 
            "expected_min_score": 25,
            "expected_action": "WARN",
            "desc": "Rule 2: Financial keywords on suspicious host"
        },
        # Rule 3: Brand Impersonation -> BLOCK
        {
            "url": "http://paypal-secure-auth.net/login", 
            "expected_classification": "HIGH RISK",
            "expected_action": "BLOCK",
            "desc": "Rule 3: Brand Impersonation + Auth"
        },
        # Rule 4: IP Trap -> BLOCK
        {
            "url": "http://192.168.1.50/signin", 
            "expected_min_score": 90,
            "expected_action": "BLOCK",
            "desc": "Rule 4: IP-based Credential Trap"
        },
        # Rule 5: Multi-Signal -> HIGH/BLOCK
        {
            "url": "http://free-winner-bonus.xyz", 
            "expected_classification": "HIGH RISK",
            "expected_action": "BLOCK",
            "desc": "Rule 5: Multi-signal (HTTP + 3 Scam Words + XYZ TLD)"
        },
        # Whitelisted -> ALLOW
        {
            "url": "https://google.com/search", 
            "expected_action": "ALLOW",
            "expected_label": "SAFE",
            "desc": "Whitelisted Domain"
        }
    ]
    
    print("--- PhishGuard Extension AI: Compliance Diagnostics ---\n")
    pass_count = 0
    
    for case in test_cases:
        url = case["url"]
        print(f"Testing: {case['desc']}")
        print(f"URL: {url}")
        
        res = model.analyze_url_phish_shield_ai(url)
        score = res["risk_score"]
        label = res["classification"]
        action = res["extension_action"]
        hover = res["hover_label"]
        
        print(f"Result: {label} ({score}%) | Action: {action} | Hover: {hover}")
        
        valid = True
        if "expected_classification" in case and label != case["expected_classification"]: valid = False
        if "expected_action" in case and action != case["expected_action"]: valid = False
        if "expected_score" in case and score < case["expected_score"]: valid = False
        if "expected_min_score" in case and score < case["expected_min_score"]: valid = False
        if "expected_label" in case and hover != case["expected_label"]: valid = False
            
        if valid:
            print("Status: PASS")
            pass_count += 1
        else:
            print(f"Status: FAIL (Expected {case.get('expected_action', 'N/A')} / {case.get('expected_classification', 'N/A')})")
        print("-" * 50)
        
    print(f"\nFinal Compliance Result: {pass_count}/{len(test_cases)} Passed")
    assert pass_count == len(test_cases), "Extension compliance check failed."

if __name__ == "__main__":
    test_extension_compliance()
