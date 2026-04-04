"""Score fusion helpers for combining phishing subsystem outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import pandas as pd


DEFAULT_WEIGHTED_FUSION_WEIGHTS = {
    "url_score": 0.30,
    "content_score": 0.40,
    "infra_score": 0.20,
    "reputation_score": 0.10,
}

DEFAULT_FUSION_META_FEATURES = [
    "url_score",
    "content_score",
    "tfidf_score",
    "bert_score",
    "infra_score",
    "reputation_score",
    "brand_impersonation_score",
    "domain_recent",
    "redirect_chain_risk",
    "hidden_iframe_count",
    "script_obfuscation_score",
    "has_login_form",
    "has_payment_form",
]


@dataclass(slots=True)
class FusionResult:
    score: int
    strategy: str
    weights: dict[str, float]
    meta_features: dict[str, float]

    def asdict(self) -> dict[str, Any]:
        return asdict(self)


class ScoreFusionEngine:
    """Combines subsystem scores using a trained meta-model or fallback weights."""

    def __init__(
        self,
        *,
        meta_model: Any | None = None,
        meta_feature_columns: list[str] | None = None,
        fallback_weights: dict[str, float] | None = None,
    ):
        self.meta_model = meta_model
        self.meta_feature_columns = meta_feature_columns or list(DEFAULT_FUSION_META_FEATURES)
        self.fallback_weights = fallback_weights or dict(DEFAULT_WEIGHTED_FUSION_WEIGHTS)

    def fuse(
        self,
        *,
        url_score: int,
        content_score: int,
        infra_score: int,
        reputation_score: int,
        extra_features: dict[str, float | int] | None = None,
    ) -> FusionResult:
        meta_features = {
            "url_score": round(url_score / 100.0, 6),
            "content_score": round(content_score / 100.0, 6),
            "infra_score": round(infra_score / 100.0, 6),
            "reputation_score": round(reputation_score / 100.0, 6),
        }
        if extra_features:
            for key, value in extra_features.items():
                meta_features[key] = float(value)

        if self.meta_model is not None and all(column in meta_features for column in self.meta_feature_columns):
            frame = pd.DataFrame(
                [[meta_features[column] for column in self.meta_feature_columns]],
                columns=self.meta_feature_columns,
            )
            probability = float(self.meta_model.predict_proba(frame)[0][1])
            return FusionResult(
                score=int(round(probability * 100)),
                strategy="meta_model",
                weights=dict(self.fallback_weights),
                meta_features=meta_features,
            )

        score = weighted_score(
            {
                "url_score": url_score,
                "content_score": content_score,
                "infra_score": infra_score,
                "reputation_score": reputation_score,
            },
            self.fallback_weights,
        )
        return FusionResult(
            score=score,
            strategy="weighted_fallback",
            weights=dict(self.fallback_weights),
            meta_features=meta_features,
        )


def weighted_score(subscores: dict[str, int], weights: dict[str, float]) -> int:
    total_weight = sum(weights.get(name, 0.0) for name in subscores)
    if total_weight <= 0:
        return 0
    total = sum(subscores[name] * weights.get(name, 0.0) for name in subscores)
    return int(round(total / total_weight))
