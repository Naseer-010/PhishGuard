"""Optional model explainability helpers."""

from __future__ import annotations

from typing import Any

import pandas as pd


def explain_with_shap(
    model: Any,
    sample_frame: pd.DataFrame,
    *,
    top_k: int = 5,
) -> list[dict[str, float | str]]:
    try:
        import shap
    except ImportError:
        return []

    try:
        explainer = shap.Explainer(model, sample_frame)
        explanation = explainer(sample_frame)
        values = explanation.values[0]
        feature_names = list(sample_frame.columns)
    except Exception:
        return []

    scored = [
        {
            "feature": feature_name,
            "impact": round(float(value), 6),
            "abs_impact": round(abs(float(value)), 6),
        }
        for feature_name, value in zip(feature_names, values)
    ]
    scored.sort(key=lambda item: item["abs_impact"], reverse=True)
    return scored[:top_k]
