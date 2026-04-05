"""Detailed tests for phishing detection model across multiple scenarios."""

from __future__ import annotations

import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.deep_risk_model.model import DeepRiskModel
from models.quick_content_model.model import QuickContentThreatModel

def test_url(url: str, model_type: str = "deep") -> None:
    print(f"\n--- Testing URL: {url} (Model: {model_type}) ---")
    
    if model_type == "deep":
        model = DeepRiskModel(timeout=6)
        report = model.analyze_url(url)
        
        print(f"Risk Score: {report['risk_score']}")
        print(f"Verdict: {report['verdict']}")
        print(f"Is Phishing: {report['is_phishing']}")
        print(f"Fusion Strategy: {report['fusion_strategy']}")
        
        print("\nThreat Indicators:")
        for indicator in report.get('threat_indicators', []):
            print(f"- [{indicator['severity'].upper()}] {indicator['type']}: {indicator['indicator']}")
            
        print("\nHuman Explanation:")
        print(json.dumps(report['human_explanation'], indent=2))
        
    else:
        model = QuickContentThreatModel(timeout=6)
        report = model.analyze_url(url)
        
        print(f"Threat Percentage: {report['threat_percentage']}")
        print(f"Risk Band: {report['risk_band']}")
        print(f"Reasons: {', '.join(report['reasons'])}")
        
        if report.get('detected_brand'):
            print(f"Detected Brand: {report['detected_brand']}")
            print(f"Brand Impersonation Score: {report['brand_impersonation_score']}")

def run_scenarios() -> None:
    scenarios = [
        "https://www.google.com",
        "http://192.168.1.1/admin/login",
        "https://microsoft-secure-login.azure-update.com/verify"
    ]
    
    for url in scenarios:
        test_url(url, model_type="deep")

if __name__ == "__main__":
    run_scenarios()
