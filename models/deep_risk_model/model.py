"""Deep phishing analysis model with trainable submodels and feed enrichment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd

from models.deep_risk_model.train_deep_model import (
    INFRA_FEATURE_COLUMNS,
    INFRA_MODEL_PATH,
    META_FEATURE_COLUMNS,
    META_MODEL_PATH,
    PAGE_FEATURE_COLUMNS,
    PAGE_MODEL_PATH,
    REPUTATION_FEATURE_COLUMNS,
    REPUTATION_MODEL_PATH,
    URL_FEATURE_COLUMNS,
)
from models.deep_risk_model.train_url_model import MODEL_PATH as LEGACY_URL_MODEL_PATH
from models.deep_risk_model.train_url_model import train as train_legacy_url_model
from models.deep_risk_model.url_feature_extractor import extract_features, get_feature_details
from models.features.deep_features import extract_live_deep_features
from models.reputation.providers import ReputationRegistry


STACKED_URL_MODEL_PATH = Path(__file__).resolve().parent / "artifacts" / "url_stack_rf.joblib"


@dataclass
class DeepRiskReport:
    url: str
    final_url: str
    risk_score: int
    verdict: str
    is_phishing: bool
    url_model_score: int
    url_heuristic_score: int
    content_risk_score: int
    infrastructure_risk_score: int
    reputation_risk_score: int
    criteria: dict[str, Any]
    threat_indicators: list[dict[str, str]]
    model_version: str


class DeepRiskModel:
    def __init__(self, timeout: int = 12, auto_train_if_missing: bool = True):
        self.timeout = timeout
        self.auto_train_if_missing = auto_train_if_missing
        self.reputation_registry = ReputationRegistry()
        self.legacy_url_model = self._load_or_train_legacy_url_model()
        self.stacked_url_model = joblib.load(STACKED_URL_MODEL_PATH) if STACKED_URL_MODEL_PATH.exists() else None
        self.page_model = joblib.load(PAGE_MODEL_PATH) if PAGE_MODEL_PATH.exists() else None
        self.infrastructure_model = joblib.load(INFRA_MODEL_PATH) if INFRA_MODEL_PATH.exists() else None
        self.reputation_model = joblib.load(REPUTATION_MODEL_PATH) if REPUTATION_MODEL_PATH.exists() else None
        self.meta_model = joblib.load(META_MODEL_PATH) if META_MODEL_PATH.exists() else None

    def analyze_url(self, url: str) -> dict[str, Any]:
        normalized = self._normalize_url(url)
        feature_details = get_feature_details(normalized)

        deep_features, page, infrastructure, reputation = extract_live_deep_features(
            normalized,
            timeout=self.timeout,
            registry=self.reputation_registry,
        )

        url_model_score = self._predict_url_score(normalized, deep_features)
        url_heuristic_score = self._feature_heuristic_score(feature_details)
        content_risk_score = self._predict_group_score(
            self.page_model,
            deep_features,
            PAGE_FEATURE_COLUMNS,
            fallback=self._page_heuristic_score(deep_features, page.fetched),
        )
        infrastructure_risk_score = self._predict_group_score(
            self.infrastructure_model,
            deep_features,
            INFRA_FEATURE_COLUMNS,
            fallback=self._infrastructure_heuristic_score(deep_features),
        )
        reputation_risk_score = self._predict_group_score(
            self.reputation_model,
            deep_features,
            REPUTATION_FEATURE_COLUMNS,
            fallback=self._reputation_heuristic_score(deep_features),
        )

        risk_score, model_version = self._final_score(
            deep_features,
            url_model_score,
            content_risk_score,
            infrastructure_risk_score,
            reputation_risk_score,
        )

        verdict = self._verdict(risk_score)
        is_phishing = risk_score >= 50

        indicators = self._build_indicators(feature_details, page.asdict(), infrastructure, reputation)
        report = DeepRiskReport(
            url=normalized,
            final_url=page.final_url,
            risk_score=risk_score,
            verdict=verdict,
            is_phishing=is_phishing,
            url_model_score=url_model_score,
            url_heuristic_score=url_heuristic_score,
            content_risk_score=content_risk_score,
            infrastructure_risk_score=infrastructure_risk_score,
            reputation_risk_score=reputation_risk_score,
            criteria={
                "feature_details": feature_details,
                "quick_features": deep_features,
                "scrape_analysis": page.asdict(),
                "infrastructure_checks": infrastructure,
                "reputation": reputation,
            },
            threat_indicators=indicators,
            model_version=model_version,
        )
        return asdict(report)

    def _load_or_train_legacy_url_model(self):
        if LEGACY_URL_MODEL_PATH.exists():
            return joblib.load(LEGACY_URL_MODEL_PATH)

        if not self.auto_train_if_missing:
            raise FileNotFoundError(f"Model not found: {LEGACY_URL_MODEL_PATH}")

        train_legacy_url_model()
        return joblib.load(LEGACY_URL_MODEL_PATH)

    def _normalize_url(self, url: str) -> str:
        value = url.strip()
        if not value:
            raise ValueError("URL is empty")
        if not value.startswith(("http://", "https://")):
            value = f"http://{value}"

        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError("Invalid URL")
        return value

    def _predict_url_score(self, normalized_url: str, deep_features: dict[str, float | int]) -> int:
        if self.stacked_url_model is not None:
            return self._predict_group_score(
                self.stacked_url_model,
                deep_features,
                URL_FEATURE_COLUMNS,
                fallback=50,
            )

        feature_values = np.array(extract_features(normalized_url)).reshape(1, -1)
        probability = float(self.legacy_url_model.predict_proba(feature_values)[0][1])
        return int(round(probability * 100))

    def _predict_group_score(
        self,
        model: Any,
        features: dict[str, float | int],
        columns: list[str],
        fallback: int,
    ) -> int:
        if model is None:
            return fallback
        frame = pd.DataFrame([[features.get(column, 0.0) for column in columns]], columns=columns)
        probability = float(model.predict_proba(frame)[0][1])
        return int(round(probability * 100))

    def _feature_heuristic_score(self, feature_details: list[dict[str, Any]]) -> int:
        critical = {
            "UsingIP",
            "ShortURL",
            "Symbol@",
            "HTTPS",
            "HTTPSDomainURL",
            "NonStdPort",
            "StatsReport",
        }
        score = 0
        for detail in feature_details:
            if detail["status"] == "danger":
                score += 8
                if detail["name"] in critical:
                    score += 10
            elif detail["status"] == "warning":
                score += 3
                if detail["name"] in critical:
                    score += 3
        return min(100, score)

    def _page_heuristic_score(self, features: dict[str, float | int], fetched: bool) -> int:
        score = 0.0
        score += min(float(features["threat_keyword_weight"]) * 2.2, 34)
        score += min(float(features["password_fields_count"]) * 10, 24)
        score += min(float(features["external_form_actions"]) * 16, 28)
        score += min(float(features["script_obfuscation_signals"]) * 5, 20)
        if float(features["has_login_form"]) > 0:
            score += 8
        if not fetched:
            score += 6
        if float(features["safe_keyword_weight"]) >= 10 and float(features["threat_keyword_weight"]) < 4:
            score -= 10
        return int(round(max(0, min(100, score))))

    def _infrastructure_heuristic_score(self, features: dict[str, float | int]) -> int:
        score = 0.0
        if float(features["is_https"]) == 0:
            score += 12
        if float(features["host_is_ip"]) > 0 or float(features["uses_ip_host"]) > 0:
            score += 24
        if float(features["has_punycode"]) > 0 or float(features["punycode_domain"]) > 0:
            score += 15
        if float(features["suspicious_tld_infra"]) > 0 or float(features["suspicious_tld"]) > 0:
            score += 15
        if float(features["dns_resolves"]) == 0:
            score += 16
        if float(features["non_standard_port"]) > 0:
            score += 8
        if float(features["tls_checked"]) > 0 and float(features["tls_valid"]) == 0:
            score += 20
        if float(features["tls_expiring_soon"]) > 0:
            score += 6
        return int(round(max(0, min(100, score))))

    def _reputation_heuristic_score(self, features: dict[str, float | int]) -> int:
        score = 0.0
        score += float(features["reputation_url_hits"]) * 45
        score += float(features["reputation_domain_hits"]) * 20
        score += float(features["reputation_source_count"]) * 10
        score = max(score, float(features["reputation_confidence"]))
        return int(round(max(0, min(100, score))))

    def _final_score(
        self,
        deep_features: dict[str, float | int],
        url_model_score: int,
        content_risk_score: int,
        infrastructure_risk_score: int,
        reputation_risk_score: int,
    ) -> tuple[int, str]:
        if self.meta_model is not None:
            meta_features = deep_features.copy()
            meta_features.update(
                {
                    "url_score": url_model_score / 100.0,
                    "page_score": content_risk_score / 100.0,
                    "infra_score": infrastructure_risk_score / 100.0,
                    "reputation_score": reputation_risk_score / 100.0,
                }
            )
            frame = pd.DataFrame([[meta_features.get(column, 0.0) for column in META_FEATURE_COLUMNS]], columns=META_FEATURE_COLUMNS)
            probability = float(self.meta_model.predict_proba(frame)[0][1])
            return int(round(probability * 100)), "deep_meta_v1"

        risk = self._weighted_score(
            [
                (url_model_score, 0.35),
                (content_risk_score, 0.25),
                (infrastructure_risk_score, 0.15),
                (reputation_risk_score, 0.25),
            ]
        )
        return risk, "deep_weighted_fallback_v1"

    def _build_indicators(
        self,
        feature_details: list[dict[str, Any]],
        scraped: dict[str, Any],
        infrastructure: dict[str, Any],
        reputation: dict[str, Any],
    ) -> list[dict[str, str]]:
        indicators: list[dict[str, str]] = []

        for detail in feature_details:
            if detail["status"] == "danger":
                indicators.append(
                    {
                        "type": "url_feature",
                        "severity": "high",
                        "indicator": f"Feature {detail['name']} flagged as danger",
                    }
                )

        if scraped.get("has_login_form"):
            indicators.append({"type": "content", "severity": "high", "indicator": "Login form detected"})
        if scraped.get("external_form_actions", 0) > 0:
            indicators.append(
                {
                    "type": "content",
                    "severity": "high",
                    "indicator": "Form action posts to external domain",
                }
            )
        if scraped.get("script_obfuscation_signals", 0) > 0:
            indicators.append(
                {
                    "type": "content",
                    "severity": "medium",
                    "indicator": "Obfuscated JavaScript patterns detected",
                }
            )
        if infrastructure.get("host_is_ip"):
            indicators.append(
                {
                    "type": "infrastructure",
                    "severity": "high",
                    "indicator": "Host uses raw IP address",
                }
            )
        if infrastructure.get("suspicious_tld"):
            indicators.append(
                {
                    "type": "infrastructure",
                    "severity": "medium",
                    "indicator": "Domain uses a high-risk TLD",
                }
            )
        if not infrastructure.get("https"):
            indicators.append(
                {
                    "type": "infrastructure",
                    "severity": "medium",
                    "indicator": "URL is not HTTPS",
                }
            )
        if reputation.get("source_count", 0) > 0:
            indicators.append(
                {
                    "type": "reputation",
                    "severity": "high",
                    "indicator": "Threat-intel feed match found",
                }
            )

        return indicators[:8]

    def _weighted_score(self, parts: list[tuple[int, float]]) -> int:
        total_weight = sum(weight for _, weight in parts)
        if total_weight == 0:
            return 0
        total = sum(score * weight for score, weight in parts)
        return int(round(total / total_weight))

    def _verdict(self, score: int) -> str:
        if score <= 29:
            return "Safe"
        if score <= 59:
            return "Suspicious"
        return "Dangerous"
