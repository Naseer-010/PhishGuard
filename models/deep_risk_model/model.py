"""
Deep Risk Model (No VirusTotal)

Combines multiple criteria:
1. URL ML score from phishing.csv-trained Random Forest
2. URL heuristic feature risk
3. Deep page content risk after scraping
4. Infrastructure and protocol risk checks
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import numpy as np
import requests
from bs4 import BeautifulSoup

from models.deep_risk_model.train_url_model import MODEL_PATH, train
from models.deep_risk_model.url_feature_extractor import extract_features, get_feature_details
from models.quick_content_model.keywords import SAFE_KEYWORDS, THREAT_KEYWORDS


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
    criteria: dict[str, Any]
    threat_indicators: list[dict[str, str]]


class DeepRiskModel:
    def __init__(self, timeout: int = 12, auto_train_if_missing: bool = True):
        self.timeout = timeout
        self.auto_train_if_missing = auto_train_if_missing
        self.model = self._load_or_train_model()

    def analyze_url(self, url: str) -> dict[str, Any]:
        normalized = self._normalize_url(url)

        feature_values = extract_features(normalized)
        feature_details = get_feature_details(normalized)

        feature_array = np.array(feature_values).reshape(1, -1)
        proba = self.model.predict_proba(feature_array)[0]
        url_model_score = int(round(float(proba[1]) * 100))

        url_heuristic_score = self._feature_heuristic_score(feature_details)
        scraped = self._scrape_deep(normalized)
        content_risk_score = self._content_risk_score(scraped)

        infrastructure = self._infrastructure_checks(normalized)
        infrastructure_risk_score = self._infrastructure_score(infrastructure)

        risk_score = self._weighted_score(
            [
                (url_model_score, 0.45),
                (url_heuristic_score, 0.20),
                (content_risk_score, 0.20),
                (infrastructure_risk_score, 0.15),
            ]
        )

        verdict = self._verdict(risk_score)
        is_phishing = risk_score >= 50

        indicators = self._build_indicators(feature_details, scraped, infrastructure)

        report = DeepRiskReport(
            url=normalized,
            final_url=scraped.get("final_url", normalized),
            risk_score=risk_score,
            verdict=verdict,
            is_phishing=is_phishing,
            url_model_score=url_model_score,
            url_heuristic_score=url_heuristic_score,
            content_risk_score=content_risk_score,
            infrastructure_risk_score=infrastructure_risk_score,
            criteria={
                "feature_details": feature_details,
                "scrape_analysis": scraped,
                "infrastructure_checks": infrastructure,
            },
            threat_indicators=indicators,
        )
        return asdict(report)

    def _load_or_train_model(self):
        if MODEL_PATH.exists():
            return joblib.load(MODEL_PATH)

        if not self.auto_train_if_missing:
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

        train()
        return joblib.load(MODEL_PATH)

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
            name = detail["name"]
            status = detail["status"]
            if status == "danger":
                score += 8
                if name in critical:
                    score += 10
            elif status == "warning":
                score += 3
                if name in critical:
                    score += 3
        return min(100, score)

    def _scrape_deep(self, url: str) -> dict[str, Any]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0.0.0 Safari/537.36"
            )
        }

        result: dict[str, Any] = {
            "fetched": False,
            "final_url": url,
            "status_code": None,
            "redirect_count": 0,
            "forms_count": 0,
            "password_fields_count": 0,
            "has_login_form": False,
            "external_form_actions": 0,
            "iframe_count": 0,
            "hidden_inputs_count": 0,
            "obfuscated_script_signals": 0,
            "threat_keyword_hits": {},
            "safe_keyword_hits": {},
            "reason": None,
        }

        try:
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=True,
                )
            except requests.exceptions.SSLError:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
                result["tls_warning"] = "ssl_verification_failed"

            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["redirect_count"] = len(response.history)

            if response.status_code >= 400:
                result["reason"] = f"http_{response.status_code}"
                return result

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            password_fields = soup.find_all("input", {"type": "password"})
            iframes = soup.find_all("iframe")
            hidden_inputs = soup.find_all("input", {"type": "hidden"})

            final_host = (urlparse(response.url).hostname or "").lower()

            external_form_actions = 0
            has_login_form = False
            for form in forms:
                form_body = form.get_text(" ", strip=True).lower()
                form_html = str(form).lower()

                action = form.get("action", "")
                action_host = (urlparse(action).hostname or "").lower()
                if action_host and final_host and action_host != final_host:
                    external_form_actions += 1

                if any(token in form_body or token in form_html for token in ("login", "sign in", "password", "username"))
            script_text = " ".join(script.get_text(" ", strip=True).lower() for script in soup.find_all("script"))
            obfuscation_tokens = (
                "eval(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  
                "atob(",
                "fromcharcode",
                "unescape(",
                "window.location",
                "settimeout(",
            )
            obfuscated_script_signals = sum(script_text.count(token) for token in obfuscation_tokens)

            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            visible_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True).lower())[:15000]

            threat_hits = self._keyword_hits(visible_text, THREAT_KEYWORDS)
            safe_hits = self._keyword_hits(visible_text, SAFE_KEYWORDS)

            result.update(
                {
                    "fetched": True,
                    "forms_count": len(forms),
                    "password_fields_count": len(password_fields),
                    "has_login_form": has_login_form,
                    "external_form_actions": external_form_actions,
                    "iframe_count": len(iframes),
                    "hidden_inputs_count": len(hidden_inputs),
                    "obfuscated_script_signals": obfuscated_script_signals,
                    "threat_keyword_hits": threat_hits,
                    "safe_keyword_hits": safe_hits,
                    "reason": None,
                }
            )
        except requests.exceptions.Timeout:
            result["reason"] = "timeout"
        except requests.exceptions.ConnectionError:
            result["reason"] = "connection_error"
        except Exception as exc:
            result["reason"] = f"error:{exc}"

        return result

    def _content_risk_score(self, scraped: dict[str, Any]) -> int:
        if not scraped.get("fetched"):
            return 50

        threat_weight = self._weighted_sum(scraped.get("threat_keyword_hits", {}), THREAT_KEYWORDS)
        safe_weight = self._weighted_sum(scraped.get("safe_keyword_hits", {}), SAFE_KEYWORDS)

        score = 100 * (threat_weight / (threat_weight + safe_weight + 1e-9))

        if scraped.get("has_login_form"):
            score += 10
        score += min(scraped.get("password_fields_count", 0) * 8, 24)
        score += min(scraped.get("external_form_actions", 0) * 12, 24)

        if scraped.get("iframe_count", 0) > 2:
            score += 10
        if scraped.get("hidden_inputs_count", 0) > 10:
            score += 8

        score += min(scraped.get("obfuscated_script_signals", 0) * 5, 20)
        if scraped.get("redirect_count", 0) > 2:
            score += 8

        if safe_weight >= 10 and threat_weight < 4:
            score -= 12

        return int(round(max(0, min(100, score))))

    def _infrastructure_checks(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = parsed.scheme
        port = parsed.port

        checks: dict[str, Any] = {
            "https": scheme == "https",
            "host_is_ip": False,
            "punycode_domain": "xn--" in host,
            "suspicious_tld": False,
            "dns_resolves": False,
            "non_standard_port": False,
            "ssl_certificate": {
                "checked": False,
                "valid": None,
                "days_to_expiry": None,
                "error": None,
            },
        }

        try:
            ipaddress.ip_address(host)
            checks["host_is_ip"] = True
        except ValueError:
            checks["host_is_ip"] = False

        suffix = host.split(".")[-1].lower() if "." in host else ""
        checks["suspicious_tld"] = suffix in {
            "zip",
            "xyz",
            "top",
            "click",
            "gq",
            "tk",
            "cf",
            "ml",
            "work",
            "country",
            "kim",
            "men",
            "download",
        }

        if port is not None and port not in {80, 443, 8080, 8443}:
            checks["non_standard_port"] = True

        try:
            socket.gethostbyname(host)
            checks["dns_resolves"] = True
        except Exception:
            checks["dns_resolves"] = False

        if scheme == "https" and host:
            checks["ssl_certificate"] = self._ssl_certificate_status(host, port or 443)

        return checks

    def _ssl_certificate_status(self, host: str, port: int) -> dict[str, Any]:
        result = {
            "checked": True,
            "valid": False,
            "days_to_expiry": None,
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    cert = secure_sock.getpeercert()

            not_after = cert.get("notAfter")
            if not_after:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_to_expiry = math.floor((expiry - now).total_seconds() / 86400)
                result["days_to_expiry"] = int(days_to_expiry)
                result["valid"] = days_to_expiry >= 0
            else:
                result["valid"] = False
                result["error"] = "missing_notAfter"
        except Exception as exc:
            result["valid"] = False
            result["error"] = str(exc)

        return result

    def _infrastructure_score(self, checks: dict[str, Any]) -> int:
        score = 0

        if not checks.get("https", False):
            score += 12
        if checks.get("host_is_ip", False):
            score += 22
        if checks.get("punycode_domain", False):
            score += 15
        if checks.get("suspicious_tld", False):
            score += 15
        if not checks.get("dns_resolves", False):
            score += 16
        if checks.get("non_standard_port", False):
            score += 8

        ssl_check = checks.get("ssl_certificate", {})
        if ssl_check.get("checked"):
            if not ssl_check.get("valid", False):
                score += 20
            elif ssl_check.get("days_to_expiry") is not None and ssl_check["days_to_expiry"] < 14:
                score += 6

        return min(100, score)

    def _build_indicators(
        self,
        feature_details: list[dict[str, Any]],
        scraped: dict[str, Any],
        infrastructure: dict[str, Any],
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
            indicators.append(
                {
                    "type": "content",
                    "severity": "high",
                    "indicator": "Login form detected",
                }
            )
        if scraped.get("external_form_actions", 0) > 0:
            indicators.append(
                {
                    "type": "content",
                    "severity": "high",
                    "indicator": "Form action posts to external domain",
                }
            )
        if scraped.get("obfuscated_script_signals", 0) > 0:
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

        return indicators

    def _weighted_score(self, parts: list[tuple[int, float]]) -> int:
        total_weight = sum(weight for _, weight in parts)
        if total_weight == 0:
            return 0
        total = sum(score * weight for score, weight in parts)
        return int(round(total / total_weight))

    def _keyword_hits(self, text: str, weighted_keywords: dict[str, int]) -> dict[str, int]:
        hits: dict[str, int] = {}
        for phrase in weighted_keywords:
            count = len(re.findall(re.escape(phrase), text))
            if count > 0:
                hits[phrase] = count
        return hits

    def _weighted_sum(self, hits: dict[str, int], weighted_keywords: dict[str, int]) -> int:
        total = 0
        for phrase, count in hits.items():
            total += weighted_keywords.get(phrase, 1) * count
        return total

    def _verdict(self, score: int) -> str:
        if score <= 30:
            return "Safe"
        if score <= 60:
            return "Suspicious"
        return "Dangerous"
