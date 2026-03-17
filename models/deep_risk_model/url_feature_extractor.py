"""
URL feature extraction for phishing.csv-compatible model training/inference.

Feature convention:
-  1: legitimate
-  0: suspicious/uncertain
- -1: phishing-like
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

import tldextract

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "tiny.cc",
    "rebrand.ly",
    "shorturl.at",
    "cutt.ly",
    "rb.gy",
}

POPULAR_DOMAINS = {
    "google",
    "youtube",
    "facebook",
    "amazon",
    "wikipedia",
    "reddit",
    "github",
    "microsoft",
    "apple",
    "linkedin",
    "instagram",
    "netflix",
    "stackoverflow",
}

SUSPICIOUS_TLDS = {
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

KNOWN_BAD_HOST_FRAGMENTS = {
    "login-verify",
    "secure-update",
    "account-recovery",
    "wallet-connect",
    "verify-now",
    "signin-check",
}

FEATURE_COLUMNS = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport",
]

TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None, cache_dir="/tmp/tldextract")


class URLContext:
    def __init__(self, raw_url: str):
        normalized = raw_url.strip()
        if not normalized.startswith(("http://", "https://")):
            normalized = f"http://{normalized}"

        self.url = normalized
        self.parsed = urlparse(normalized)
        self.hostname = (self.parsed.hostname or "").lower()
        self.path = self.parsed.path or ""
        self.query = self.parsed.query or ""
        self.fragment = self.parsed.fragment or ""

        ext = TLD_EXTRACTOR(self.hostname)
        self.subdomain = ext.subdomain.lower() if ext.subdomain else ""
        self.domain = ext.domain.lower() if ext.domain else ""
        self.suffix = ext.suffix.lower() if ext.suffix else ""


def _hostname_is_ip(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _using_ip(ctx: URLContext) -> int:
    return -1 if _hostname_is_ip(ctx.hostname) else 1


def _long_url(ctx: URLContext) -> int:
    length = len(ctx.url)
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _short_url(ctx: URLContext) -> int:
    host = ctx.hostname
    for shortener in SHORTENER_DOMAINS:
        if host == shortener or host.endswith(f".{shortener}"):
            return -1
    return 1


def _symbol_at(ctx: URLContext) -> int:
    return -1 if "@" in ctx.url else 1


def _redirecting_double_slash(ctx: URLContext) -> int:
    scheme_marker = f"{ctx.parsed.scheme}://" if ctx.parsed.scheme else ""
    remaining = ctx.url[len(scheme_marker) :] if scheme_marker else ctx.url
    return -1 if "//" in remaining else 1


def _prefix_suffix(ctx: URLContext) -> int:
    return -1 if "-" in ctx.domain else 1


def _subdomains(ctx: URLContext) -> int:
    if not ctx.subdomain or ctx.subdomain == "www":
        return 1
    labels = [label for label in ctx.subdomain.split(".") if label and label != "www"]
    if len(labels) <= 1:
        return 0
    return -1


def _https_state(ctx: URLContext) -> int:
    if ctx.parsed.scheme == "https":
        return 1
    if ctx.parsed.scheme == "http":
        return -1
    return 0


def _domain_reg_length(ctx: URLContext) -> int:
    if not ctx.domain:
        return -1
    if ctx.suffix in SUSPICIOUS_TLDS:
        return -1
    if len(ctx.domain) <= 3:
        return 0
    if ctx.suffix in {"com", "org", "net", "edu", "gov", "mil"}:
        return 1
    return 0


def _favicon(ctx: URLContext) -> int:
    return 1


def _non_std_port(ctx: URLContext) -> int:
    if ctx.parsed.port is None:
        return 1
    if ctx.parsed.port in {80, 443}:
        return 1
    if ctx.parsed.port in {8080, 8443}:
        return 0
    return -1


def _https_domain_url(ctx: URLContext) -> int:
    return -1 if "https" in ctx.hostname else 1


def _request_url(ctx: URLContext) -> int:
    payload = f"{ctx.path}?{ctx.query}".lower()
    markers = sum(payload.count(token) for token in ("http://", "https://", "%2f%2f", "//"))
    if markers == 0:
        return 1
    if markers <= 2:
        return 0
    return -1


def _anchor_url(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    if "javascript:" in raw:
        return -1
    if ctx.fragment:
        return 0
    return 1


def _links_in_script_tags(ctx: URLContext) -> int:
    return 1


def _server_form_handler(ctx: URLContext) -> int:
    return 0


def _info_email(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    if "mailto:" in raw:
        return -1
    if re.search(r"[\w.+-]+@[\w.-]+", raw):
        return -1
    return 1


def _abnormal_url(ctx: URLContext) -> int:
    if not ctx.hostname:
        return -1
    if "%00" in ctx.url.lower() or "\\x00" in ctx.url.lower():
        return -1
    if ctx.domain and ctx.path.lower().count(ctx.domain) > 1:
        return 0
    return 1


def _website_forwarding(ctx: URLContext) -> int:
    redirects = ctx.url.count("//") - 1
    if redirects <= 0:
        return 1
    if redirects == 1:
        return 0
    return -1


def _status_bar_customization(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    return -1 if "onmouseover" in raw else 1


def _disable_right_click(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    return -1 if "contextmenu" in raw or "event.button==2" in raw else 1


def _using_popup_window(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    return -1 if "window.open" in raw or "popup" in raw else 1


def _iframe_redirection(ctx: URLContext) -> int:
    raw = ctx.url.lower()
    return -1 if "iframe" in raw else 1


def _age_of_domain(ctx: URLContext) -> int:
    if not ctx.domain:
        return -1
    digit_count = sum(ch.isdigit() for ch in ctx.domain)
    if len(ctx.domain) < 4 or digit_count >= 4:
        return -1
    if "-" in ctx.domain:
        return 0
    return 1


def _dns_recording(ctx: URLContext) -> int:
    if not ctx.hostname:
        return -1
    try:
        socket.gethostbyname(ctx.hostname)
        return 1
    except Exception:
        return -1


def _website_traffic(ctx: URLContext) -> int:
    if ctx.domain in POPULAR_DOMAINS:
        return 1
    if ctx.suffix in {"com", "org", "net"} and len(ctx.domain) >= 5 and "-" not in ctx.domain:
        return 0
    return -1


def _page_rank(ctx: URLContext) -> int:
    if ctx.domain in POPULAR_DOMAINS:
        return 1
    digit_count = sum(ch.isdigit() for ch in ctx.domain)
    if "-" in ctx.domain or digit_count >= 4:
        return -1
    return 0


def _google_index(ctx: URLContext) -> int:
    if _hostname_is_ip(ctx.hostname):
        return -1
    if ctx.suffix in SUSPICIOUS_TLDS:
        return -1
    if ctx.domain in POPULAR_DOMAINS:
        return 1
    return 0


def _links_pointing_to_page(ctx: URLContext) -> int:
    depth = len([segment for segment in ctx.path.split("/") if segment])
    if depth <= 1:
        return 1
    if depth <= 3:
        return 0
    return -1


def _stats_report(ctx: URLContext) -> int:
    host = ctx.hostname
    if any(fragment in host for fragment in KNOWN_BAD_HOST_FRAGMENTS):
        return -1
    return 1


def extract_features(url: str) -> list[int]:
    ctx = URLContext(url)
    return [
        _using_ip(ctx),
        _long_url(ctx),
        _short_url(ctx),
        _symbol_at(ctx),
        _redirecting_double_slash(ctx),
        _prefix_suffix(ctx),
        _subdomains(ctx),
        _https_state(ctx),
        _domain_reg_length(ctx),
        _favicon(ctx),
        _non_std_port(ctx),
        _https_domain_url(ctx),
        _request_url(ctx),
        _anchor_url(ctx),
        _links_in_script_tags(ctx),
        _server_form_handler(ctx),
        _info_email(ctx),
        _abnormal_url(ctx),
        _website_forwarding(ctx),
        _status_bar_customization(ctx),
        _disable_right_click(ctx),
        _using_popup_window(ctx),
        _iframe_redirection(ctx),
        _age_of_domain(ctx),
        _dns_recording(ctx),
        _website_traffic(ctx),
        _page_rank(ctx),
        _google_index(ctx),
        _links_pointing_to_page(ctx),
        _stats_report(ctx),
    ]


def get_feature_details(url: str) -> list[dict[str, int | str]]:
    values = extract_features(url)
    details: list[dict[str, int | str]] = []
    for feature_name, value in zip(FEATURE_COLUMNS, values):
        status = "safe" if value == 1 else ("warning" if value == 0 else "danger")
        details.append({"name": feature_name, "value": value, "status": status})
    return details
