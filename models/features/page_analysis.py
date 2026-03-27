"""HTML scraping and DOM/content feature extraction."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from models.features.brand_detection import detect_brand_impersonation
from models.quick_content_model.keywords import (
    BRAND_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    SAFE_KEYWORDS,
    THREAT_KEYWORDS,
    URGENCY_KEYWORDS,
)


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36"
)

SCRIPT_TOKENS = (
    "eval(",
    "atob(",
    "fromcharcode",
    "unescape(",
    "window.location",
    "settimeout(",
    "document.write",
)

PAYMENT_FIELD_TOKENS = (
    "card",
    "credit",
    "debit",
    "cvv",
    "cvc",
    "expiry",
    "billing",
    "payment",
)


@dataclass(slots=True)
class PageAnalysis:
    fetched: bool
    url: str
    final_url: str
    status_code: int | None
    redirect_count: int
    title_text: str
    visible_text: str
    text_length: int
    title_length: int
    visible_word_count: int
    forms_count: int
    password_fields_count: int
    payment_fields_count: int
    hidden_inputs_count: int
    iframe_count: int
    total_links_count: int
    external_links_count: int
    external_resource_count: int
    resource_count: int
    external_form_actions: int
    has_login_form: bool
    has_payment_form: bool
    favicon_host_mismatch: bool
    detected_brand: str | None
    brand_match_count: int
    brand_impersonation_detected: bool
    brand_impersonation_score: int
    script_obfuscation_signals: int
    threat_keyword_hits: dict[str, int]
    safe_keyword_hits: dict[str, int]
    urgency_keyword_hits: dict[str, int]
    credential_keyword_hits: dict[str, int]
    financial_keyword_hits: dict[str, int]
    brand_keyword_hits: dict[str, int]
    reason: str | None = None
    tls_warning: str | None = None

    @property
    def external_link_ratio(self) -> float:
        if self.total_links_count == 0:
            return 0.0
        return round(self.external_links_count / self.total_links_count, 6)

    @property
    def external_resource_ratio(self) -> float:
        if self.resource_count == 0:
            return 0.0
        return round(self.external_resource_count / self.resource_count, 6)

    def asdict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["external_link_ratio"] = self.external_link_ratio
        payload["external_resource_ratio"] = self.external_resource_ratio
        return payload


def fetch_page(url: str, timeout: int = 10) -> tuple[str | None, PageAnalysis]:
    headers = {"User-Agent": USER_AGENT}

    try:
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=True)
            tls_warning = None
        except requests.exceptions.SSLError:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
            tls_warning = "ssl_verification_failed"

        analysis = analyze_html(
            url=url,
            html=response.text,
            final_url=response.url,
            status_code=response.status_code,
            redirect_count=len(response.history),
            fetched=response.status_code < 400,
            reason=None if response.status_code < 400 else f"http_{response.status_code}",
            tls_warning=tls_warning,
        )
        return response.text, analysis
    except requests.exceptions.Timeout:
        return None, empty_page_analysis(url, reason="timeout")
    except requests.exceptions.ConnectionError:
        return None, empty_page_analysis(url, reason="connection_error")
    except Exception as exc:
        return None, empty_page_analysis(url, reason=f"error:{exc}")


def analyze_html(
    url: str,
    html: str,
    final_url: str = "",
    status_code: int | None = None,
    redirect_count: int = 0,
    fetched: bool = True,
    reason: str | None = None,
    tls_warning: str | None = None,
) -> PageAnalysis:
    resolved_final_url = final_url or url
    soup = BeautifulSoup(html, "html.parser")

    forms = soup.find_all("form")
    password_fields = soup.find_all("input", {"type": "password"})
    hidden_inputs = soup.find_all("input", {"type": "hidden"})
    payment_fields = _payment_fields(soup)
    iframes = soup.find_all("iframe")
    anchors = soup.find_all("a", href=True)
    title_text = soup.title.get_text(" ", strip=True).lower() if soup.title else ""

    final_host = (urlparse(resolved_final_url).hostname or "").lower()

    external_links_count = 0
    total_links_count = 0
    for anchor in anchors:
        href = anchor.get("href", "")
        if not href.startswith(("http://", "https://", "//", "/")):
            continue
        total_links_count += 1
        target_host = (urlparse(urljoin(resolved_final_url, href)).hostname or "").lower()
        if final_host and target_host and target_host != final_host:
            external_links_count += 1

    resource_count = 0
    external_resource_count = 0
    for tag_name, attr_name in (("script", "src"), ("img", "src"), ("link", "href")):
        for tag in soup.find_all(tag_name):
            value = tag.get(attr_name, "")
            if not value:
                continue
            resource_count += 1
            target_host = (urlparse(urljoin(resolved_final_url, value)).hostname or "").lower()
            if final_host and target_host and target_host != final_host:
                external_resource_count += 1

    external_form_actions = 0
    has_login_form = False
    for form in forms:
        form_body = form.get_text(" ", strip=True).lower()
        form_html = str(form).lower()
        action = form.get("action", "")
        action_host = (urlparse(urljoin(resolved_final_url, action)).hostname or "").lower()
        if action_host and final_host and action_host != final_host:
            external_form_actions += 1
        if any(token in form_body or token in form_html for token in ("login", "sign in", "password", "username")):
            has_login_form = True

    has_payment_form = len(payment_fields) > 0

    favicon_host_mismatch = False
    favicon = soup.find("link", rel=_rel_contains_icon)
    if favicon and favicon.get("href"):
        icon_host = (urlparse(urljoin(resolved_final_url, favicon["href"])).hostname or "").lower()
        favicon_host_mismatch = bool(final_host and icon_host and icon_host != final_host)

    script_text = " ".join(script.get_text(" ", strip=True).lower() for script in soup.find_all("script"))
    script_obfuscation_signals = sum(script_text.count(token) for token in SCRIPT_TOKENS)

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    visible_text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True).lower())[:20000]
    visible_word_count = len(visible_text.split()) if visible_text else 0
    brand_detection = detect_brand_impersonation(
        visible_text=visible_text,
        title_text=title_text,
        final_url=resolved_final_url,
        has_sensitive_form=has_login_form or has_payment_form,
    )

    return PageAnalysis(
        fetched=fetched,
        url=url,
        final_url=resolved_final_url,
        status_code=status_code,
        redirect_count=redirect_count,
        title_text=title_text,
        visible_text=visible_text,
        text_length=len(visible_text),
        title_length=len(title_text),
        visible_word_count=visible_word_count,
        forms_count=len(forms),
        password_fields_count=len(password_fields),
        payment_fields_count=len(payment_fields),
        hidden_inputs_count=len(hidden_inputs),
        iframe_count=len(iframes),
        total_links_count=total_links_count,
        external_links_count=external_links_count,
        external_resource_count=external_resource_count,
        resource_count=resource_count,
        external_form_actions=external_form_actions,
        has_login_form=has_login_form,
        has_payment_form=has_payment_form,
        favicon_host_mismatch=favicon_host_mismatch,
        detected_brand=brand_detection.detected_brand,
        brand_match_count=brand_detection.match_count,
        brand_impersonation_detected=brand_detection.impersonation_detected,
        brand_impersonation_score=brand_detection.score,
        script_obfuscation_signals=script_obfuscation_signals,
        threat_keyword_hits=count_keywords(visible_text, THREAT_KEYWORDS),
        safe_keyword_hits=count_keywords(visible_text, SAFE_KEYWORDS),
        urgency_keyword_hits=count_keywords(visible_text, URGENCY_KEYWORDS),
        credential_keyword_hits=count_keywords(visible_text, CREDENTIAL_KEYWORDS),
        financial_keyword_hits=count_keywords(visible_text, FINANCIAL_KEYWORDS),
        brand_keyword_hits=count_keywords(visible_text, BRAND_KEYWORDS),
        reason=reason,
        tls_warning=tls_warning,
    )


def empty_page_analysis(url: str, reason: str) -> PageAnalysis:
    return PageAnalysis(
        fetched=False,
        url=url,
        final_url=url,
        status_code=None,
        redirect_count=0,
        title_text="",
        visible_text="",
        text_length=0,
        title_length=0,
        visible_word_count=0,
        forms_count=0,
        password_fields_count=0,
        payment_fields_count=0,
        hidden_inputs_count=0,
        iframe_count=0,
        total_links_count=0,
        external_links_count=0,
        external_resource_count=0,
        resource_count=0,
        external_form_actions=0,
        has_login_form=False,
        has_payment_form=False,
        favicon_host_mismatch=False,
        detected_brand=None,
        brand_match_count=0,
        brand_impersonation_detected=False,
        brand_impersonation_score=0,
        script_obfuscation_signals=0,
        threat_keyword_hits={},
        safe_keyword_hits={},
        urgency_keyword_hits={},
        credential_keyword_hits={},
        financial_keyword_hits={},
        brand_keyword_hits={},
        reason=reason,
        tls_warning=None,
    )


def load_html(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="ignore")


def load_network_snapshot(path: str | Path) -> dict[str, Any]:
    snapshot_path = Path(path)
    if not snapshot_path.exists():
        return {}
    return json.loads(snapshot_path.read_text(encoding="utf-8"))


def count_keywords(text: str, weighted_keywords: dict[str, int]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for phrase in weighted_keywords:
        count = len(re.findall(re.escape(phrase), text))
        if count > 0:
            hits[phrase] = count
    return hits


def weighted_hit_sum(hits: dict[str, int], weighted_keywords: dict[str, int]) -> int:
    total = 0
    for phrase, count in hits.items():
        total += weighted_keywords.get(phrase, 1) * count
    return total


def _rel_contains_icon(value: Any) -> bool:
    if not value:
        return False
    if isinstance(value, (list, tuple)):
        raw = " ".join(str(item) for item in value)
    else:
        raw = str(value)
    return "icon" in raw.lower()


def _payment_fields(soup: BeautifulSoup) -> list[Any]:
    matched_fields: list[Any] = []
    for input_tag in soup.find_all("input"):
        joined = " ".join(
            str(input_tag.get(attribute, "")).lower()
            for attribute in ("name", "id", "placeholder", "autocomplete", "aria-label")
        )
        if any(token in joined for token in PAYMENT_FIELD_TOKENS):
            matched_fields.append(input_tag)
    return matched_fields
