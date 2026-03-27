"""Brand impersonation detection helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import tldextract


TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None, cache_dir="/tmp/tldextract")

BRAND_RULES = {
    "paypal": {"tokens": ("paypal",), "domains": {"paypal.com"}},
    "microsoft": {"tokens": ("microsoft", "office365", "office 365", "outlook"), "domains": {"microsoft.com", "office.com", "live.com", "outlook.com"}},
    "google": {"tokens": ("google", "gmail", "google workspace"), "domains": {"google.com", "gmail.com"}},
    "apple": {"tokens": ("apple", "icloud"), "domains": {"apple.com", "icloud.com"}},
    "amazon": {"tokens": ("amazon", "prime video"), "domains": {"amazon.com"}},
    "facebook": {"tokens": ("facebook", "meta"), "domains": {"facebook.com", "meta.com"}},
    "instagram": {"tokens": ("instagram",), "domains": {"instagram.com"}},
    "linkedin": {"tokens": ("linkedin",), "domains": {"linkedin.com"}},
    "netflix": {"tokens": ("netflix",), "domains": {"netflix.com"}},
    "dropbox": {"tokens": ("dropbox",), "domains": {"dropbox.com"}},
    "adobe": {"tokens": ("adobe", "acrobat"), "domains": {"adobe.com"}},
    "whatsapp": {"tokens": ("whatsapp",), "domains": {"whatsapp.com"}},
}


@dataclass(slots=True)
class BrandImpersonationResult:
    detected_brand: str | None
    domain_matches_brand: bool
    impersonation_detected: bool
    match_count: int
    score: int

    def asdict(self) -> dict[str, str | int | bool | None]:
        return asdict(self)


def detect_brand_impersonation(
    visible_text: str,
    title_text: str,
    final_url: str,
    has_sensitive_form: bool,
) -> BrandImpersonationResult:
    content = f"{title_text} {visible_text[:5000]}".lower()
    registrable_domain = extract_registrable_domain(final_url)

    dominant_brand: str | None = None
    dominant_count = 0
    domain_matches = True

    for brand, rule in BRAND_RULES.items():
        count = sum(content.count(token) for token in rule["tokens"])
        if count > dominant_count:
            dominant_brand = brand
            dominant_count = count
            domain_matches = _domain_matches_brand(registrable_domain, brand, rule["domains"])

    impersonation_detected = False
    score = 0
    if dominant_brand and dominant_count > 0:
        if not domain_matches and (has_sensitive_form or dominant_count >= 2):
            impersonation_detected = True
            score = 18 + min(dominant_count * 4, 16)
            if has_sensitive_form:
                score += 12

    return BrandImpersonationResult(
        detected_brand=dominant_brand,
        domain_matches_brand=domain_matches,
        impersonation_detected=impersonation_detected,
        match_count=dominant_count,
        score=min(100, score),
    )


def extract_registrable_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    ext = TLD_EXTRACTOR(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _domain_matches_brand(registrable_domain: str, brand: str, allowed_domains: set[str]) -> bool:
    if not registrable_domain:
        return False
    if registrable_domain in allowed_domains:
        return True
    return brand in registrable_domain
