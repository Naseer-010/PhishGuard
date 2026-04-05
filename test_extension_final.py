import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from models.deep_risk_model.model import DeepRiskModel

def test_extension_compliance():
    model = DeepRiskModel()
    
    test_cases = [
        {
            "url": "http://claim-free-reward.top", 
            "expected_action": "BLOCK",
            "desc": "Rule 1: Scam Bait"
        },
        {
            "url": "http://verify-bank-update.net", 
            "expected_action": "BLOCK",
            "desc": "Rule 2: Financial"
        },
        {
            "url": "http://paypal-secure-auth.net/login", 
            "expected_action": "BLOCK",
            "desc": "Rule 3: Impersonation"
        },
        {
            "url": "http://192.168.1.50/signin", 
            "expected_action": "BLOCK",
            "desc": "Rule 4: IP Trap"
        },
        {
            "url": "http://free-winner-bonus.xyz", 
            "expected_action": "BLOCK",
            "desc": "Rule 5: Multi-signal"
        },
        {
            "url": "https://google.com/search", 
            "expected_action": "ALLOW",
            "desc": "Whitelisted"
        }
    ]
    
    print("--- PhishGuard Extension AI: Strict Compliance Check ---")
    pass_count = 0
    
    for case in test_cases:
        url = case["url"]
        res = model.analyze_url_phish_shield_ai(url)
        action = res["extension_action"]
        
        valid = (action == case["expected_action"])
        status = "[PASS]" if valid else f"[FAIL] (Expected {case['expected_action']}, got {action})"
        
        print(f"{case['desc']: <20} | URL: {url: <35} | {status}")
        
        if valid:
            pass_count += 1
            
    print(f"\nFinal Result: {pass_count}/{len(test_cases)}")
    if pass_count != len(test_cases):
        sys.exit(1)

if __name__ == "__main__":
    test_extension_compliance()
