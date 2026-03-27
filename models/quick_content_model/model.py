"""Trainable quick phishing model with a heuristic fallback."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import pandas as pd

from models.common.schemas import QuickPrediction
from models.common.text_models import DistilBertTextModel, TfidfTextModel
from models.features.page_analysis import PageAnalysis
from models.features.quick_features import QUICK_FEATURE_COLUMNS, extract_live_quick_features
from models.quick_content_model.train_quick_model import MODEL_PATH
from models.quick_content_model.train_distilbert_model import MODEL_DIR as DISTILBERT_MODEL_DIR
from models.quick_content_model.train_text_tfidf_model import TEXT_MODEL_PATH


class QuickContentThreatModel:
    """Lightweight extension-facing phishing scorer."""

    def __init__(self, timeout: int = 10, model_path: str | Path = MODEL_PATH):
        self.timeout = timeout
        self.model_path = Path(model_path)
        self.model = joblib.load(self.model_path) if self.model_path.exists() else None
        self.text_model = TfidfTextModel(TEXT_MODEL_PATH)
        self.distilbert_model = DistilBertTextModel(DISTILBERT_MODEL_DIR)

    def analyze_url(self, url: str) -> dict[str, Any]:
        normalized = self._normalize_url(url)
        features, page = extract_live_quick_features(normalized, timeout=self.timeout)
        threat_percentage, model_version, auxiliary_scores = self._score(features, page)
        reasons = self._reason_strings(features, page)
        risk_band = self._risk_band(threat_percentage)
        text_explanations = self.text_model.explain_text(page.visible_text, top_k=5) if page.visible_text else []

        prediction = QuickPrediction(
            url=normalized,
            final_url=page.final_url,
            risk_score=threat_percentage,
            risk_band=risk_band,
            fetched=page.fetched,
            model_version=model_version,
            reasons=reasons,
            features=features,
            diagnostics={
                "status_code": page.status_code,
                "redirect_count": page.redirect_count,
                "reason": page.reason,
            },
        )

        payload = prediction.asdict()
        payload.update(
            {
                "threat_percentage": threat_percentage,
                "tabular_model_score": auxiliary_scores["tabular_model_score"],
                "text_model_score": auxiliary_scores["text_model_score"],
                "bert_model_score": auxiliary_scores["bert_model_score"],
                "brand_impersonation_score": page.brand_impersonation_score,
                "brand_impersonation_detected": page.brand_impersonation_detected,
                "detected_brand": page.detected_brand,
                "threat_word_count": sum(page.threat_keyword_hits.values()),
                "safe_word_count": sum(page.safe_keyword_hits.values()),
                "threat_word_hits": page.threat_keyword_hits,
                "safe_word_hits": page.safe_keyword_hits,
                "forms_count": page.forms_count,
                "password_fields_count": page.password_fields_count,
                "payment_fields_count": page.payment_fields_count,
                "has_login_form": page.has_login_form,
                "has_payment_form": page.has_payment_form,
                "fetched": page.fetched,
                "reason": page.reason,
                "text_explanations": text_explanations,
            }
        )
        return payload

    def _score(self, features: dict[str, float | int], page: PageAnalysis) -> tuple[int, str, dict[str, int | None]]:
        if self.model is not None:
            feature_frame = pd.DataFrame([[features[column] for column in QUICK_FEATURE_COLUMNS]], columns=QUICK_FEATURE_COLUMNS)
            tabular_score = int(round(float(self.model.predict_proba(feature_frame)[0][1]) * 100))
            base_version = "quick_model_v1"
        else:
            tabular_score = self._heuristic_score(features, page)
            base_version = "heuristic_fallback_v1"

        text_score = self.text_model.predict_score(page.visible_text) if page.visible_text else None
        bert_score = self.distilbert_model.predict_score(page.visible_text) if page.visible_text else None

        parts: list[tuple[int, float]] = [
            (tabular_score, 0.45),
            (page.brand_impersonation_score, 0.10),
        ]
        version_tokens = [base_version]

        if text_score is not None:
            parts.append((text_score, 0.30))
            version_tokens.append("tfidf_text")
        if bert_score is not None:
            parts.append((bert_score, 0.15))
            version_tokens.append("distilbert")

        score = self._weighted_score(parts)
        return score, "+".join(version_tokens), {
            "tabular_model_score": tabular_score,
            "text_model_score": text_score,
            "bert_model_score": bert_score,
        }

    def _heuristic_score(self, features: dict[str, float | int], page: PageAnalysis) -> int:
        heuristic = 0.0
        heuristic += min(float(features["uses_ip_host"]) * 22, 22)
        heuristic += min(float(features["has_punycode"]) * 12, 12)
        heuristic += min(float(features["suspicious_tld"]) * 12, 12)
        heuristic += min(float(features["password_fields_count"]) * 10, 25)
        heuristic += min(float(features["payment_fields_count"]) * 10, 25)
        heuristic += min(float(features["external_form_actions"]) * 18, 28)
        heuristic += min(float(features["script_obfuscation_signals"]) * 5, 20)
        heuristic += min(float(features["threat_keyword_weight"]) * 2.4, 30)
        heuristic += min(float(features["urgency_keyword_count"]) * 1.5, 18)
        heuristic += min(float(features["credential_keyword_count"]) * 1.5, 18)
        heuristic += float(features["has_login_form"]) * 10
        heuristic += float(features["has_payment_form"]) * 10
        heuristic += float(features["brand_impersonation_score"])
        heuristic += float(features["external_resource_ratio"]) * 15

        if not page.fetched:
            heuristic += 8
        if float(features["safe_keyword_weight"]) >= 10 and float(features["threat_keyword_weight"]) <= 4:
            heuristic -= 12

        return int(round(max(0, min(100, heuristic))))

    def _reason_strings(self, features: dict[str, float | int], page: PageAnalysis) -> list[str]:
        reasons: list[str] = []
        if float(features["uses_ip_host"]) > 0:
            reasons.append("URL uses a raw IP address")
        if float(features["has_punycode"]) > 0:
            reasons.append("Domain contains punycode")
        if float(features["suspicious_tld"]) > 0:
            reasons.append("Domain uses a high-risk TLD")
        if page.has_login_form:
            reasons.append("Login form detected")
        if page.password_fields_count > 0:
            reasons.append("Password input detected")
        if page.payment_fields_count > 0:
            reasons.append("Payment or card fields detected")
        if page.external_form_actions > 0:
            reasons.append("Form posts to an external host")
        if page.brand_impersonation_detected and page.detected_brand:
            reasons.append(f"Brand impersonation suspected for {page.detected_brand}")
        if page.script_obfuscation_signals > 0:
            reasons.append("Suspicious script obfuscation patterns detected")
        if sum(page.threat_keyword_hits.values()) > 0:
            reasons.append("Threat-oriented language found in page text")
        if not page.fetched and page.reason:
            reasons.append(f"Page fetch failed: {page.reason}")
        return reasons[:5]

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

    def _risk_band(self, score: int) -> str:
        if score <= 29:
            return "safe"
        if score <= 59:
            return "suspicious"
        return "dangerous"

    def _weighted_score(self, parts: list[tuple[int, float]]) -> int:
        total_weight = sum(weight for _, weight in parts)
        if total_weight <= 0:
            return 0
        weighted_total = sum(score * weight for score, weight in parts)
        return int(round(weighted_total / total_weight))
