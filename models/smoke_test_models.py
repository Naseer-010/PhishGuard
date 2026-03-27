"""Smoke tests for quick and deep model modules."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from models.deep_risk_model.model import DeepRiskModel
from models.quick_content_model.model import QuickContentThreatModel

def run() -> None:
    quick_model = QuickContentThreatModel(timeout=4)
    quick_report = quick_model.analyze_url("example.invalid/login")
    assert "threat_percentage" in quick_report
    assert 0 <= quick_report["threat_percentage"] <= 100
    assert "model_version" in quick_report
    assert "risk_band" in quick_report
    assert "brand_impersonation_score" in quick_report
    assert "text_explanations" in quick_report

    deep_model = DeepRiskModel(timeout=4)
    deep_report = deep_model.analyze_url("example.invalid/login")
    assert "risk_score" in deep_report
    assert 0 <= deep_report["risk_score"] <= 100
    assert "reputation_risk_score" in deep_report
    assert "model_version" in deep_report
    assert "text_model_score" in deep_report
    assert "criteria" in deep_report and "explanations" in deep_report["criteria"]
    assert "human_explanation" in deep_report
    assert "fusion_strategy" in deep_report

    print("Smoke tests passed")
    print(
        f"quick_threat_percentage={quick_report['threat_percentage']} "
        f"deep_risk_score={deep_report['risk_score']}"
    )


if __name__ == "__main__":
    run()
