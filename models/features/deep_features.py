"""Feature extraction for deep multi-signal phishing analysis."""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from models.features.page_analysis import PageAnalysis, fetch_page, load_network_snapshot
from models.features.quick_features import QUICK_FEATURE_COLUMNS, build_quick_feature_dict
from models.reputation.providers import ReputationRegistry


DEEP_FEATURE_COLUMNS = QUICK_FEATURE_COLUMNS + [
    "dns_resolves",
    "resolved_ip_count",
    "host_is_ip",
    "punycode_domain",
    "suspicious_tld_infra",
    "non_standard_port",
    "whois_available",
    "domain_age_days",
    "domain_recent",
    "tls_checked",
    "tls_valid",
    "tls_days_to_expiry",
    "tls_expiring_soon",
    "reputation_url_hits",
    "reputation_domain_hits",
    "reputation_source_count",
    "reputation_confidence",
]


def extract_live_deep_features(
    url: str,
    timeout: int = 12,
    registry: ReputationRegistry | None = None,
) -> tuple[dict[str, float | int], PageAnalysis, dict[str, Any], dict[str, Any]]:
    _, page = fetch_page(url, timeout=timeout)
    infrastructure = collect_infrastructure_snapshot(page.final_url or url, timeout=timeout)
    reputation = (registry or ReputationRegistry()).lookup(page.final_url or url).asdict()
    features = build_deep_feature_dict(page.final_url or url, page, infrastructure, reputation)
    return features, page, infrastructure, reputation


def build_deep_feature_row(
    sample_id: str,
    url: str,
    label: int,
    label_source: str,
    collected_at: str,
    final_url: str,
    quick_features: dict[str, float | int],
    infrastructure: dict[str, Any],
    reputation: dict[str, Any],
) -> dict[str, Any]:
    row = {
        "sample_id": sample_id,
        "url": url,
        "domain_group": registrable_host(final_url or url),
        "label": label,
        "label_source": label_source,
        "collected_at": collected_at,
    }
    row.update(quick_features)
    row.update(deep_feature_suffix(infrastructure, reputation))
    return row


def build_deep_feature_dict(
    url: str,
    page: PageAnalysis,
    infrastructure: dict[str, Any],
    reputation: dict[str, Any],
) -> dict[str, float | int]:
    features = build_quick_feature_dict(url, page)
    features.update(deep_feature_suffix(infrastructure, reputation))
    return features


def build_deep_feature_row_from_snapshot(
    sample_id: str,
    url: str,
    label: int,
    label_source: str,
    collected_at: str,
    final_url: str,
    quick_features: dict[str, float | int],
    network_path: str,
) -> dict[str, Any]:
    snapshot = load_network_snapshot(network_path)
    infrastructure = snapshot.get("infrastructure", {})
    reputation = snapshot.get("reputation", {})
    row = {
        "sample_id": sample_id,
        "url": url,
        "domain_group": registrable_host(final_url or url),
        "label": label,
        "label_source": label_source,
        "collected_at": collected_at,
    }
    row.update(quick_features)
    row.update(deep_feature_suffix(infrastructure, reputation))
    return row


def collect_infrastructure_snapshot(url: str, timeout: int = 12) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme
    port = parsed.port

    snapshot: dict[str, Any] = {
        "https": scheme == "https",
        "dns_resolves": False,
        "resolved_ips": [],
        "host_is_ip": False,
        "punycode_domain": "xn--" in host,
        "suspicious_tld": False,
        "non_standard_port": False,
        "domain_registration": {
            "checked": False,
            "available": False,
            "age_days": None,
            "registrar": None,
            "error": None,
        },
        "ssl_certificate": {
            "checked": False,
            "valid": False,
            "days_to_expiry": None,
            "issuer_common_name": None,
            "error": None,
        },
    }

    try:
        ipaddress.ip_address(host)
        snapshot["host_is_ip"] = True
    except ValueError:
        snapshot["host_is_ip"] = False

    suffix = host.split(".")[-1].lower() if "." in host else ""
    snapshot["suspicious_tld"] = suffix in {
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
        snapshot["non_standard_port"] = True

    if host:
        try:
            _, _, ip_addresses = socket.gethostbyname_ex(host)
            snapshot["dns_resolves"] = True
            snapshot["resolved_ips"] = sorted(set(ip_addresses))
        except Exception:
            snapshot["dns_resolves"] = False

    if host and not snapshot["host_is_ip"]:
        snapshot["domain_registration"] = domain_registration_snapshot(host)

    if scheme == "https" and host:
        snapshot["ssl_certificate"] = ssl_certificate_status(host, port or 443, timeout)

    return snapshot


def ssl_certificate_status(host: str, port: int, timeout: int) -> dict[str, Any]:
    result = {
        "checked": True,
        "valid": False,
        "days_to_expiry": None,
        "issuer_common_name": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()

        not_after = cert.get("notAfter")
        issuer = cert.get("issuer")
        if issuer:
            issuer_parts = []
            for item in issuer:
                for key, value in item:
                    if key == "commonName":
                        issuer_parts.append(value)
            if issuer_parts:
                result["issuer_common_name"] = issuer_parts[0]
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            result["days_to_expiry"] = int(math.floor((expiry - now).total_seconds() / 86400))
            result["valid"] = result["days_to_expiry"] >= 0
        else:
            result["error"] = "missing_notAfter"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def deep_feature_suffix(infrastructure: dict[str, Any], reputation: dict[str, Any]) -> dict[str, float | int]:
    ssl_certificate = infrastructure.get("ssl_certificate", {})
    registration = infrastructure.get("domain_registration", {})
    days_to_expiry = ssl_certificate.get("days_to_expiry")
    age_days = registration.get("age_days")
    return {
        "dns_resolves": int(bool(infrastructure.get("dns_resolves"))),
        "resolved_ip_count": len(infrastructure.get("resolved_ips", [])),
        "host_is_ip": int(bool(infrastructure.get("host_is_ip"))),
        "punycode_domain": int(bool(infrastructure.get("punycode_domain"))),
        "suspicious_tld_infra": int(bool(infrastructure.get("suspicious_tld"))),
        "non_standard_port": int(bool(infrastructure.get("non_standard_port"))),
        "whois_available": int(bool(registration.get("available"))),
        "domain_age_days": int(age_days) if age_days is not None else -1,
        "domain_recent": int(age_days is not None and age_days < 30),
        "tls_checked": int(bool(ssl_certificate.get("checked"))),
        "tls_valid": int(bool(ssl_certificate.get("valid"))),
        "tls_days_to_expiry": int(days_to_expiry) if days_to_expiry is not None else -1,
        "tls_expiring_soon": int(days_to_expiry is not None and days_to_expiry < 14),
        "reputation_url_hits": int(reputation.get("url_hits", 0)),
        "reputation_domain_hits": int(reputation.get("domain_hits", 0)),
        "reputation_source_count": int(reputation.get("source_count", 0)),
        "reputation_confidence": int(reputation.get("confidence", 0)),
    }


def registrable_host(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def domain_registration_snapshot(host: str) -> dict[str, Any]:
    result = {
        "checked": False,
        "available": False,
        "age_days": None,
        "registrar": None,
        "error": None,
    }

    try:
        import whois
    except ImportError:
        result["error"] = "python-whois_not_installed"
        return result

    try:
        record = whois.whois(host)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_values = [item for item in creation_date if item]
            creation_date = min(creation_values) if creation_values else None

        result["checked"] = True
        result["registrar"] = str(getattr(record, "registrar", "") or "") or None
        if creation_date:
            creation_dt = creation_date
            if creation_dt.tzinfo is None:
                creation_dt = creation_dt.replace(tzinfo=timezone.utc)
            result["available"] = True
            result["age_days"] = max(0, int((datetime.now(timezone.utc) - creation_dt).total_seconds() // 86400))
        else:
            result["error"] = "creation_date_missing"
    except Exception as exc:
        result["error"] = str(exc)

    return result
