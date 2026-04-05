"""Deep phishing analysis model with trainable submodels and feed enrichment."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import re
from typing import Any
from urllib.parse import urlparse

from models.common.fusion import DEFAULT_FUSION_META_FEATURES, ScoreFusionEngine
from models.common.human_explanations import build_deep_human_explanation
from models.common.explainability import explain_with_shap
from models.common.text_models import DistilBertTextModel, TfidfTextModel
from models.deep_risk_model.train_deep_model import (
    INFRA_FEATURE_COLUMNS,
    INFRA_MODEL_PATH,
    META_MODEL_PATH,
    PAGE_FEATURE_COLUMNS,
    PAGE_MODEL_PATH,
    REPUTATION_FEATURE_COLUMNS,
    REPUTATION_MODEL_PATH,
    URL_FEATURE_COLUMNS,
)
from models.deep_risk_model.train_url_model import MODEL_PATH as LEGACY_URL_MODEL_PATH
from models.deep_risk_model.train_url_model import train as train_legacy_url_model
from models.deep_risk_model.train_distilbert_model import MODEL_DIR as DISTILBERT_MODEL_DIR
from models.deep_risk_model.train_text_tfidf_model import TEXT_MODEL_PATH
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
    text_model_score: int | None
    bert_model_score: int | None
    infrastructure_risk_score: int
    reputation_risk_score: int
    subscores: dict[str, int]
    human_explanation: dict[str, Any]
    fusion_strategy: str
    criteria: dict[str, Any]
    threat_indicators: list[dict[str, str]]
    model_version: str


GLOBAL_TRUST_LIST_SIMPLE = [
    "google", "microsoft", "amazon", "apple", "netflix", 
    "github", "facebook", "linkedin", "twitter", "instagram",
    "paypal", "stripe", "bankofamerica", "chase", "wellsfargo",
    "adobe", "zoom", "slack", "discord", "spotify"
]


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
        self.text_model = TfidfTextModel(TEXT_MODEL_PATH) if TEXT_MODEL_PATH.exists() else None
        self.distilbert_model = DistilBertTextModel(DISTILBERT_MODEL_DIR) if DISTILBERT_MODEL_DIR.exists() else None
        self.fusion_engine = ScoreFusionEngine(
            meta_model=self.meta_model,
            meta_feature_columns=list(DEFAULT_FUSION_META_FEATURES),
        )

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
        raw_page_model_score = self._predict_group_score(
            self.page_model,
            deep_features,
            PAGE_FEATURE_COLUMNS,
            fallback=self._page_heuristic_score(deep_features, page.fetched),
        )
        
        # --- PROTECTED TEXT MODEL SCORES ---
        text_model_score = self.text_model.predict_score(page.visible_text) if self.text_model and page.visible_text else None
        bert_model_score = self.distilbert_model.predict_score(page.visible_text) if self.distilbert_model and page.visible_text else None
        # -----------------------------------
        
        content_risk_score = self._content_score(
            raw_page_model_score=raw_page_model_score,
            text_model_score=text_model_score,
            bert_model_score=bert_model_score,
            brand_impersonation_score=page.brand_impersonation_score,
            payment_fields_count=page.payment_fields_count,
            redirect_chain_risk_score=page.redirect_chain_risk_score,
            hidden_iframe_count=page.hidden_iframe_count,
            script_obfuscation_signals=page.script_obfuscation_signals,
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

        fusion_result = self._final_score(
            deep_features=deep_features,
            url_model_score=url_model_score,
            content_risk_score=content_risk_score,
            text_model_score=text_model_score,
            bert_model_score=bert_model_score,
            infrastructure_risk_score=infrastructure_risk_score,
            reputation_risk_score=reputation_risk_score,
        )
        risk_score = fusion_result.score
        model_version = self._model_version(fusion_result.strategy, text_model_score, bert_model_score)

        verdict = self._verdict(risk_score)
        is_phishing = risk_score >= 50

        indicators = self._build_indicators(feature_details, page.asdict(), infrastructure, reputation)
        explanations = self._explanations(
            deep_features,
            page,
            raw_page_model_score=raw_page_model_score,
            infrastructure_risk_score=infrastructure_risk_score,
        )
        human_explanation = build_deep_human_explanation(
            score=risk_score,
            url_model_score=url_model_score,
            content_score=content_risk_score,
            infrastructure_score=infrastructure_risk_score,
            reputation_score=reputation_risk_score,
            page=page.asdict(),
            infrastructure=infrastructure,
            reputation=reputation,
            text_terms=explanations.get("text_terms", []),
        )
        report = DeepRiskReport(
            url=normalized,
            final_url=page.final_url,
            risk_score=risk_score,
            verdict=verdict,
            is_phishing=is_phishing,
            url_model_score=url_model_score,
            url_heuristic_score=url_heuristic_score,
            content_risk_score=content_risk_score,
            text_model_score=text_model_score,
            bert_model_score=bert_model_score,
            infrastructure_risk_score=infrastructure_risk_score,
            reputation_risk_score=reputation_risk_score,
            subscores={
                "url": url_model_score,
                "content": content_risk_score,
                "infrastructure": infrastructure_risk_score,
                "reputation": reputation_risk_score,
            },
            human_explanation=human_explanation,
            fusion_strategy=fusion_result.strategy,
            criteria={
                "feature_details": feature_details,
                "quick_features": deep_features,
                "scrape_analysis": page.asdict(),
                "infrastructure_checks": infrastructure,
                "reputation": reputation,
                "explanations": explanations,
                "fusion": fusion_result.asdict(),
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

    def analyze_url_phish_shield_ai(self, url: str) -> dict[str, Any]:
        """PhishGuard Extension AI: Strict 8-Dimension forensic engine (Single-URL, Extension Action Schema)."""
        input_raw = url.strip()
        
        # 1. STRICT INPUT VALIDATION
        # Detect multiple URLs
        url_count = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', input_raw))
        if url_count > 1:
            return self._invalid_input_response(input_raw, "Multiple URLs detected. Analysis requires a single target.")
            
        # Detect random/noisy text (must have at least one dot to be a valid domain-like target)
        if "." not in input_raw or " " in input_raw:
            return self._invalid_input_response(input_raw, "Input does not resemble a valid URL or host domain.")

        # Normalize Bare Domains
        normalized = input_raw
        if not normalized.startswith(("http://", "https://")):
            normalized = f"http://{normalized}"
            
        try:
            parsed = urlparse(normalized)
            if not parsed.hostname:
                return self._invalid_input_response(input_raw, "Malformed URL: Incomplete domain structure.")
        except Exception:
            return self._invalid_input_response(input_raw, "Malformed URL: Unparseable input.")

        # 2. BROWSER SECURITY ANALYSIS FRAMEWORK (8 Dimensions)
        from models.deep_risk_model.url_feature_extractor import (
            get_feature_details, calculate_shannon_entropy, fuzzy_brand_proximity
        )
        feature_details = get_feature_details(normalized)
        rule_score = self._feature_heuristic_score(feature_details)
        
        domain = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        subdomains = domain.split(".")
        root_domain = ".".join(subdomains[-2:]) if len(subdomains) >= 2 else domain
        domain_entropy = calculate_shannon_entropy(domain)
        
        ai_score = 0
        ai_reasons = []

        # List of critical phishing/scam/financial words
        scam_bait_words = ["free", "giftcard", "winner", "claim", "prize", "bonus", "reward"]
        financial_security_words = [
            "bank", "billing", "payment", "wallet", "verify", "login", "secure", "account", 
            "password", "update", "authentication", "confirm", "reset", "invoice", "auth", "signin"
        ]
        phishing_lures = ["alert", "support", "urgent", "unlock", "recovery", "limit"]
        
        all_suspicious_words = scam_bait_words + financial_security_words + phishing_lures
        
        # 1. ROOT DOMAIN TRUST (Whitelisting check)
        is_trusted = root_domain in GLOBAL_TRUST_LIST_SIMPLE or any(b == root_domain.split(".")[0] for b in GLOBAL_TRUST_LIST_SIMPLE)
        if is_trusted:
            ai_score -= 50
        
        # 2. BRAND IMPERSONATION
        brands = GLOBAL_TRUST_LIST_SIMPLE + ["amazon", "netflix", "chase", "americanexpress", "wellsfargo", "bankofamerica", "support", "signin", "auth"]
        is_brand_impersonation = False
        for brand in brands:
            if brand in domain and brand not in root_domain:
                ai_score += 45
                ai_reasons.append(f"Brand impersonation detected: Institutional keyword '{brand}' misused in subdomains.")
                is_brand_impersonation = True

        # 3. SCAM / PHISHING WORDING
        found_suspicious_words = [w for w in all_suspicious_words if w in normalized.lower()]
        if found_suspicious_words:
            word_penalty = len(found_suspicious_words) * 15
            ai_score += min(60, word_penalty)
            ai_reasons.append(f"Suspicious intent detected: URL contains high-risk keywords ({', '.join(found_suspicious_words[:3])}).")

        # 4. STRUCTURAL DECEPTION
        if any(any(k in s for k in all_suspicious_words) for s in subdomains[:-2]):
            ai_score += 35
            ai_reasons.append("Structural deception: Brand or trust keywords identified in deceptive subdomain segments.")

        # 5. LEXICAL ABNORMALITY
        if domain_entropy > 3.8:
            ai_score += 40
            ai_reasons.append(f"Lexical abnormality: High entropy ({domain_entropy:.2f}) suggests DGA/machine-generated domain.")
        elif re.search(r"[0-9\-]{4,}", domain) or len(domain) > 35:
            ai_score += 20
            ai_reasons.append("Lexical abnormality: Unnatural domain length or hyphenation patterns.")

        # 6. SECURITY SIGNALS
        if normalized.startswith("http://"):
            ai_score += 25
            ai_reasons.append("Security signal: Insecure protocol (HTTP) identified.")
        if bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)):
            ai_score += 50
            ai_reasons.append("Security signal: Host uses raw IP address instead of registered domain.")

        # 7. PATH / ENDPOINT INTENT
        intent_matches = [w for w in ["login", "verify", "account", "update", "reset", "claim", "winner", "payment", "invoice", "wallet", "support", "auth", "signin"] if w in path or w in query]
        if intent_matches:
            ai_score += 30
            ai_reasons.append(f"Endpoint intent: Path structure targets sensitive user actions ({', '.join(intent_matches[:2])}).")

        # 8. SOCIAL ENGINEERING INTENT
        is_scam_bait = any(w in normalized.lower() for w in scam_bait_words)
        is_financial = any(w in normalized.lower() for w in financial_security_words)
        if is_scam_bait:
            ai_score += 30
            ai_reasons.append("Social engineering: Lure-based components (gift/reward/prize) identified.")

        # --- NON-NEGOTIABLE SAFETY RULES (Override Engine) ---
        ai_score = max(0, min(100, ai_score))
        
        # FUSION LOGIC (60% Neural, 40% Rules for conservative bias)
        final_score = int(round((rule_score * 0.4) + (ai_score * 0.6)))
        
        # Apply Rule 1: No LOW RISK for scam bait + unknown domain
        if is_scam_bait and not is_trusted:
            final_score = max(final_score, 25)
            if ai_score > 50: final_score = max(final_score, 75) # Usually HIGH
            
        # Apply Rule 2: No LOW RISK for financial/security + suspicious domain
        if is_financial and not is_trusted:
            final_score = max(final_score, 25)

        # Apply Rule 3: Brand name in URL but not root domain -> MEDIUM/HIGH
        if is_brand_impersonation:
            final_score = max(final_score, 35)
            if is_financial or is_scam_bait: final_score = max(final_score, 80)

        # Apply Rule 4: IP-based Credential Trap -> HIGH
        is_ip_host = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
        is_ip_credential_trap = is_ip_host and (is_financial or "auth" in normalized.lower())
        if is_ip_credential_trap:
            final_score = max(final_score, 90)

        # Apply Rule 5: Multi-Signal Sharp Increase
        if len(found_suspicious_words) >= 3 or (is_brand_impersonation and normalized.startswith("http://")):
            final_score = max(final_score, 70)

        final_score = max(0, min(100, final_score))

        # --- CLASSIFICATION & EXTENSION DECISION ENGINE ---
        if final_score <= 24:
            classification = "LOW RISK"
            confidence = 0.95 if is_trusted else 0.75
            extension_action = "ALLOW"
            hover_label = "SAFE"
            badge_status = "OK"
            overlay_recommended = False
            redirect_to_warning_page = False
        elif final_score <= 59:
            classification = "MEDIUM RISK"
            confidence = 0.75
            extension_action = "WARN"
            hover_label = "RISKY"
            badge_status = "MED"
            overlay_recommended = True if final_score > 40 else False
            redirect_to_warning_page = True
        else:
            classification = "HIGH RISK"
            confidence = 0.95
            
            # Aggressive blocking for clear traps/scams (Rule-based escalation)
            is_clear_trap = is_brand_impersonation or is_ip_credential_trap or is_scam_bait or len(found_suspicious_words) >= 3
            if final_score >= 85 or (final_score >= 70 and is_clear_trap):
                extension_action = "BLOCK"
            else:
                extension_action = "WARN"

            hover_label = "RISKY"
            badge_status = "RISK"
            overlay_recommended = True
            redirect_to_warning_page = True

        return {
            "input": input_raw,
            "normalized_url": normalized,
            "valid": True,
            "risk_score": final_score,
            "classification": classification,
            "confidence": confidence,
            "extension_action": extension_action,
            "hover_label": hover_label,
            "badge_status": badge_status,
            "overlay_recommended": overlay_recommended,
            "redirect_to_warning_page": redirect_to_warning_page,
            "reasons": list(set(ai_reasons + [d["name"] for d in feature_details if d["status"] == "danger"])),
            "summary": f"{classification} detected: Strict extension logic recommends {extension_action} state."
        }

    def _invalid_input_response(self, input_raw: str, reason: str) -> dict[str, Any]:
        """Standardized response for malformed or invalid inputs."""
        return {
            "input": input_raw,
            "normalized_url": None,
            "valid": False,
            "risk_score": None,
            "classification": "INVALID INPUT",
            "confidence": 0.0,
            "reasons": [reason],
            "summary": "Analysis aborted: The provided input is malformed or not a single valid URL."
        }

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
        probability = float(model.predict_proba([[features.get(column, 0.0) for column in columns]])[0][1])
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
            "DomainRegLen",
            "EntropyHigh",
            "FuzzyBrand",
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
        score += min(float(features["payment_fields_count"]) * 10, 24)
        score += min(float(features["external_form_actions"]) * 16, 28)
        score += min(float(features["script_obfuscation_signals"]) * 5, 20)
        score += min(float(features["brand_impersonation_score"]), 24)
        if float(features["has_login_form"]) > 0:
            score += 8
        if float(features["has_payment_form"]) > 0:
            score += 8
        if not fetched:
            score += 6
        if float(features["safe_keyword_weight"]) >= 10 and float(features["threat_keyword_weight"]) < 4:
            score -= 10
        return int(round(max(0, min(100, score))))

    def _infrastructure_heuristic_score(self, features: dict[str, float | int]) -> int:
        score = 0.0
        if float(features["is_https"]) == 0:
            score += 25  # Increased from 12
        if float(features["whois_available"]) == 0:
            score += 8   # Increased from 4
        if float(features["domain_recent"]) > 0:
            score += 30  # Increased from 18
        if float(features["host_is_ip"]) > 0 or float(features["uses_ip_host"]) > 0:
            score += 40  # Increased from 24
        if float(features["has_punycode"]) > 0 or float(features["punycode_domain"]) > 0:
            score += 20  # Increased from 15
        if float(features["suspicious_tld_infra"]) > 0 or float(features["suspicious_tld"]) > 0:
            score += 25  # Increased from 15
        if float(features["dns_resolves"]) == 0:
            score += 20  # Increased from 16
        if float(features["resolved_ip_count"]) == 0:
            score += 10  # Increased from 6
        if float(features["non_standard_port"]) > 0:
            score += 12  # Increased from 8
        if float(features["tls_checked"]) > 0 and float(features["tls_valid"]) == 0:
            score += 30  # Increased from 20
        if float(features["tls_expiring_soon"]) > 0:
            score += 10  # Increased from 6
        return int(round(max(0, min(100, score))))

    def _reputation_heuristic_score(self, features: dict[str, float | int]) -> int:
        score = 0.0
        score += float(features["reputation_url_hits"]) * 45
        score += float(features["reputation_domain_hits"]) * 20
        score += float(features["reputation_source_count"]) * 10
        score = max(score, float(features["reputation_confidence"]))
        return int(round(max(0, min(100, score))))

    def _content_score(
        self,
        *,
        raw_page_model_score: int,
        text_model_score: int | None,
        bert_model_score: int | None,
        brand_impersonation_score: int,
        payment_fields_count: int,
        redirect_chain_risk_score: int,
        hidden_iframe_count: int,
        script_obfuscation_signals: int,
    ) -> int:
        parts: list[tuple[int, float]] = [
            (raw_page_model_score, 0.35),
            (brand_impersonation_score, 0.10),
            (redirect_chain_risk_score, 0.10),
            (min(100, hidden_iframe_count * 20), 0.05),
            (min(100, script_obfuscation_signals * 12), 0.05),
        ]
        if text_model_score is not None:
            parts.append((text_model_score, 0.30))
        if bert_model_score is not None:
            parts.append((bert_model_score, 0.15))
        if payment_fields_count > 0:
            parts.append((min(100, payment_fields_count * 18), 0.10))
        return self._weighted_score(parts)

    def _final_score(
        self,
        *,
        deep_features: dict[str, float | int],
        url_model_score: int,
        content_risk_score: int,
        text_model_score: int | None,
        bert_model_score: int | None,
        infrastructure_risk_score: int,
        reputation_risk_score: int,
    ):
        return self.fusion_engine.fuse(
            url_score=url_model_score,
            content_score=content_risk_score,
            infra_score=infrastructure_risk_score,
            reputation_score=reputation_risk_score,
            extra_features={
                "brand_impersonation_score": float(deep_features.get("brand_impersonation_score", 0)) / 100.0,
                "tfidf_score": 0.0 if text_model_score is None else float(text_model_score) / 100.0,
                "bert_score": 0.0 if bert_model_score is None else float(bert_model_score) / 100.0,
                "domain_recent": float(deep_features.get("domain_recent", 0)),
                "redirect_chain_risk": float(deep_features.get("redirect_chain_risk_score", 0)) / 100.0,
                "hidden_iframe_count": float(deep_features.get("hidden_iframe_count", 0)),
                "script_obfuscation_score": float(deep_features.get("script_obfuscation_signals", 0)) / 100.0,
                "has_login_form": float(deep_features.get("has_login_form", 0)),
                "has_payment_form": float(deep_features.get("has_payment_form", 0)),
            },
        )

    def _explanations(
        self,
        deep_features: dict[str, float | int],
        page: Any,
        *,
        raw_page_model_score: int,
        infrastructure_risk_score: int,
    ) -> dict[str, Any]:
        explanations: dict[str, Any] = {
            # --- PROTECTED TEXT TERMS ---
            "text_terms": self.text_model.explain_text(page.visible_text, top_k=5) if self.text_model and page.visible_text else [],
            "page_model_shap": [],
            "infra_model_shap": [],
        }

        if self.page_model is not None:
            page_frame = pd.DataFrame([[deep_features.get(column, 0.0) for column in PAGE_FEATURE_COLUMNS]], columns=PAGE_FEATURE_COLUMNS)
            explanations["page_model_shap"] = explain_with_shap(self.page_model, page_frame, top_k=5)

        if self.infrastructure_model is not None:
            infra_frame = pd.DataFrame([[deep_features.get(column, 0.0) for column in INFRA_FEATURE_COLUMNS]], columns=INFRA_FEATURE_COLUMNS)
            explanations["infra_model_shap"] = explain_with_shap(self.infrastructure_model, infra_frame, top_k=5)

        explanations["summary"] = [
            {"feature": "page_model_score", "impact": raw_page_model_score},
            {"feature": "infrastructure_score", "impact": infrastructure_risk_score},
            {"feature": "brand_impersonation_score", "impact": page.brand_impersonation_score},
        ]
        return explanations

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
        if scraped.get("has_payment_form"):
            indicators.append({"type": "content", "severity": "high", "indicator": "Payment or card fields detected"})
        if scraped.get("external_form_actions", 0) > 0:
            indicators.append(
                {
                    "type": "content",
                    "severity": "high",
                    "indicator": "Form action posts to external domain",
                }
            )
        if scraped.get("redirect_chain_suspicious"):
            indicators.append(
                {
                    "type": "content",
                    "severity": "medium",
                    "indicator": "Suspicious redirect chain detected",
                }
            )
        if scraped.get("hidden_iframe_count", 0) > 0:
            indicators.append(
                {
                    "type": "content",
                    "severity": "medium",
                    "indicator": "Hidden iframe detected",
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
        if scraped.get("brand_impersonation_detected") and scraped.get("detected_brand"):
            indicators.append(
                {
                    "type": "content",
                    "severity": "high",
                    "indicator": f"Brand impersonation suspected for {scraped['detected_brand']}",
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
        registration = infrastructure.get("domain_registration", {})
        if registration.get("age_days") is not None and registration["age_days"] < 30:
            indicators.append(
                {
                    "type": "infrastructure",
                    "severity": "high",
                    "indicator": f"Domain is very new ({registration['age_days']} days old)",
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
        if score <= 39:
            return "Safe"
        if score <= 74:
            return "Suspicious"
        return "Dangerous"

    def _model_version(
        self,
        fusion_strategy: str,
        text_model_score: int | None,
        bert_model_score: int | None,
    ) -> str:
        tokens = [f"deep_{fusion_strategy}_v1"]
        if text_model_score is not None:
            tokens.append("tfidf_text")
        if bert_model_score is not None:
            tokens.append("distilbert")
        return "+".join(tokens)
