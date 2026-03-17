"""
Quick Content Threat Model

Workflow:
1. Receive URL
2. Scrape webpage text and form signals
3. Compare threat-word intensity vs safe-word intensity
4. Return threat percentage (0-100)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .keywords import SAFE_KEYWORDS, THREAT_KEYWORDS


@dataclass
class QuickThreatResult:
    url: str
    final_url: str
    threat_percentage: int
    threat_word_count: int
    safe_word_count: int
    threat_word_hits: dict[str, int]
    safe_word_hits: dict[str, int]
    forms_count: int
    password_fields_count: int
    has_login_form: bool
    fetched: bool
    reason: str | None


class QuickContentThreatModel:
    """Threat-word vs safe-word classifier over scraped webpage content."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def analyze_url(self, url: str) -> dict[str, Any]:
        normalized = self._normalize_url(url)
        scraped = self._scrape(normalized)

        if not scraped["fetched"]:
            result = QuickThreatResult(
                url=normalized,
                final_url=normalized,
                threat_percentage=50,
                threat_word_count=0,
                safe_word_count=0,
                threat_word_hits={},
                safe_word_hits={},
                forms_count=0,
                password_fields_count=0,
                has_login_form=False,
                fetched=False,
                reason=scraped.get("reason", "fetch_failed"),
            )
            return asdict(result)

        text = scraped["text"]
        threat_hits, threat_score = self._score_keywords(text, THREAT_KEYWORDS)
        safe_hits, safe_score = self._score_keywords(text, SAFE_KEYWORDS)

        # Base score from threat/safe balance.
        balance = threat_score / (threat_score + safe_score + 1e-9)
        score = balance * 100

        # Structural adjustment from forms and password fields.
        if scraped["has_login_form"]:
            score += 12
        score += min(scraped["password_fields_count"] * 7, 20)

        # Penalize very high safe signal.
        if safe_score >= 12 and threat_score <= 4:
            score -= 15

        threat_percentage = int(round(max(0, min(100, score))))

        result = QuickThreatResult(
            url=normalized,
            final_url=scraped["final_url"],
            threat_percentage=threat_percentage,
            threat_word_count=sum(threat_hits.values()),
            safe_word_count=sum(safe_hits.values()),
            threat_word_hits=threat_hits,
            safe_word_hits=safe_hits,
            forms_count=scraped["forms_count"],
            password_fields_count=scraped["password_fields_count"],
            has_login_form=scraped["has_login_form"],
            fetched=True,
            reason=None,
        )
        return asdict(result)

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

    def _scrape(self, url: str) -> dict[str, Any]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0.0.0 Safari/537.36"
            )
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

            if response.status_code >= 400:
                return {
                    "fetched": False,
                    "reason": f"http_{response.status_code}",
                }

            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            password_fields = soup.find_all("input", {"type": "password"})

            has_login_form = False
            for form in forms:
                body = form.get_text(" ", strip=True).lower()
                html = str(form).lower()
                if any(token in body or token in html for token in ("login", "sign in", "password", "username")):
                    has_login_form = True
                    break

            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True).lower())[:12000]

            return {
                "fetched": True,
                "final_url": response.url,
                "text": text,
                "forms_count": len(forms),
                "password_fields_count": len(password_fields),
                "has_login_form": has_login_form,
            }
        except requests.exceptions.Timeout:
            return {"fetched": False, "reason": "timeout"}
        except requests.exceptions.ConnectionError:
            return {"fetched": False, "reason": "connection_error"}
        except Exception as exc:
            return {"fetched": False, "reason": f"error:{exc}"}

    def _score_keywords(self, text: str, weighted_keywords: dict[str, int]) -> tuple[dict[str, int], int]:
        hits: dict[str, int] = {}
        score = 0

        for phrase, weight in weighted_keywords.items():
            count = len(re.findall(re.escape(phrase), text))
            if count > 0:
                hits[phrase] = count
                score += count * weight

        return hits, score
