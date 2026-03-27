"""Feature extraction for the extension-grade quick model."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import tldextract

from models.features.page_analysis import PageAnalysis, analyze_html, fetch_page, load_html, weighted_hit_sum
from models.quick_content_model.keywords import (
    BRAND_KEYWORDS,
    CREDENTIAL_KEYWORDS,
    FINANCIAL_KEYWORDS,
    SAFE_KEYWORDS,
    THREAT_KEYWORDS,
    URGENCY_KEYWORDS,
)
from models.deep_risk_model.url_feature_extractor import FEATURE_COLUMNS, extract_features


TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None, cache_dir="/tmp/tldextract")

QUICK_FEATURE_COLUMNS = [
    "uses_ip_host",
    "url_length",
    "subdomain_depth",
    "has_at_symbol",
    "has_punycode",
    "suspicious_tld",
    "hyphen_count",
    "digit_ratio",
    "path_depth",
    "query_length",
    "is_https",
    "redirect_count",
    "text_length",
    "visible_word_count",
    "forms_count",
    "password_fields_count",
    "hidden_inputs_count",
    "iframe_count",
    "external_links_count",
    "external_link_ratio",
    "resource_count",
    "external_resource_count",
    "external_resource_ratio",
    "external_form_actions",
    "has_login_form",
    "favicon_host_mismatch",
    "script_obfuscation_signals",
    "threat_keyword_count",
    "threat_keyword_weight",
    "safe_keyword_count",
    "safe_keyword_weight",
    "urgency_keyword_count",
    "credential_keyword_count",
    "financial_keyword_count",
    "brand_keyword_count",
] + [f"url_feature__{name}" for name in FEATURE_COLUMNS]


def extract_live_quick_features(url: str, timeout: int = 10) -> tuple[dict[str, float | int], PageAnalysis]:
    _, page = fetch_page(url, timeout=timeout)
    return build_quick_feature_dict(url, page), page


def build_quick_feature_row(
    sample_id: str,
    url: str,
    label: int,
    label_source: str,
    collected_at: str,
    final_url: str,
    html: str,
    status_code: int | None,
    redirect_count: int,
) -> dict[str, Any]:
    page = analyze_html(
        url=url,
        html=html,
        final_url=final_url or url,
        status_code=status_code,
        redirect_count=redirect_count,
        fetched=True,
    )
    row = {
        "sample_id": sample_id,
        "url": url,
        "domain_group": registrable_domain(final_url or url),
        "label": label,
        "label_source": label_source,
        "collected_at": collected_at,
    }
    row.update(build_quick_feature_dict(url, page))
    return row


def build_quick_feature_dict(url: str, page: PageAnalysis) -> dict[str, float | int]:
    parsed = urlparse(page.final_url or url)
    host = (parsed.hostname or "").lower()
    ext = TLD_EXTRACTOR(host)
    subdomain = ext.subdomain.lower() if ext.subdomain else ""
    suffix = ext.suffix.lower() if ext.suffix else ""
    path_depth = len([segment for segment in parsed.path.split("/") if segment])
    digit_count = sum(char.isdigit() for char in url)

    threat_weight = weighted_hit_sum(page.threat_keyword_hits, THREAT_KEYWORDS)
    safe_weight = weighted_hit_sum(page.safe_keyword_hits, SAFE_KEYWORDS)

    feature_values = extract_features(page.final_url or url)
    features: dict[str, float | int] = {
        "uses_ip_host": 1 if feature_values[0] == -1 else 0,
        "url_length": len(page.final_url or url),
        "subdomain_depth": max(0, len([label for label in subdomain.split(".") if label and label != "www"])),
        "has_at_symbol": 1 if "@" in (page.final_url or url) else 0,
        "has_punycode": 1 if "xn--" in host else 0,
        "suspicious_tld": 1 if suffix in {"zip", "xyz", "top", "click", "gq", "tk", "cf", "ml", "work", "country", "kim", "men", "download"} else 0,
        "hyphen_count": host.count("-"),
        "digit_ratio": round(digit_count / max(1, len(page.final_url or url)), 6),
        "path_depth": path_depth,
        "query_length": len(parsed.query or ""),
        "is_https": 1 if parsed.scheme == "https" else 0,
        "redirect_count": page.redirect_count,
        "text_length": page.text_length,
        "visible_word_count": page.visible_word_count,
        "forms_count": page.forms_count,
        "password_fields_count": page.password_fields_count,
        "hidden_inputs_count": page.hidden_inputs_count,
        "iframe_count": page.iframe_count,
        "external_links_count": page.external_links_count,
        "external_link_ratio": page.external_link_ratio,
        "resource_count": page.resource_count,
        "external_resource_count": page.external_resource_count,
        "external_resource_ratio": page.external_resource_ratio,
        "external_form_actions": page.external_form_actions,
        "has_login_form": int(page.has_login_form),
        "favicon_host_mismatch": int(page.favicon_host_mismatch),
        "script_obfuscation_signals": page.script_obfuscation_signals,
        "threat_keyword_count": sum(page.threat_keyword_hits.values()),
        "threat_keyword_weight": threat_weight,
        "safe_keyword_count": sum(page.safe_keyword_hits.values()),
        "safe_keyword_weight": safe_weight,
        "urgency_keyword_count": weighted_hit_sum(page.urgency_keyword_hits, URGENCY_KEYWORDS),
        "credential_keyword_count": weighted_hit_sum(page.credential_keyword_hits, CREDENTIAL_KEYWORDS),
        "financial_keyword_count": weighted_hit_sum(page.financial_keyword_hits, FINANCIAL_KEYWORDS),
        "brand_keyword_count": weighted_hit_sum(page.brand_keyword_hits, BRAND_KEYWORDS),
    }
    for name, value in zip(FEATURE_COLUMNS, feature_values):
        features[f"url_feature__{name}"] = value
    return features


def build_quick_feature_row_from_html_path(
    sample_id: str,
    url: str,
    label: int,
    label_source: str,
    collected_at: str,
    final_url: str,
    html_path: str,
    status_code: int | None,
    redirect_count: int,
) -> dict[str, Any]:
    html = load_html(html_path)
    return build_quick_feature_row(
        sample_id=sample_id,
        url=url,
        label=label,
        label_source=label_source,
        collected_at=collected_at,
        final_url=final_url,
        html=html,
        status_code=status_code,
        redirect_count=redirect_count,
    )


def registrable_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    ext = TLD_EXTRACTOR(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host
