"""Human-friendly phishing explanation builders."""

from __future__ import annotations

from typing import Any


def build_deep_human_explanation(
    *,
    score: int,
    url_model_score: int,
    content_score: int,
    infrastructure_score: int,
    reputation_score: int,
    page: dict[str, Any],
    infrastructure: dict[str, Any],
    reputation: dict[str, Any],
    text_terms: list[dict[str, float | str]] | None = None,
) -> dict[str, Any]:
    severity = severity_label(score)
    reasons: list[dict[str, Any]] = []

    registration = infrastructure.get("domain_registration", {})
    domain_age = registration.get("age_days")
    if domain_age is not None and domain_age < 30:
        reasons.append(
            _reason(
                f"Domain appears very new ({domain_age} days old)",
                max(12, min(28, 30 - int(domain_age))),
                "infrastructure",
            )
        )

    if page.get("has_login_form") and page.get("password_fields_count", 0) > 0:
        reasons.append(
            _reason(
                "Contains a login form requesting a password",
                22,
                "content",
            )
        )

    if page.get("has_payment_form") or page.get("payment_fields_count", 0) > 0:
        reasons.append(
            _reason(
                "Requests payment or card details",
                20,
                "content",
            )
        )

    if page.get("brand_impersonation_detected") and page.get("detected_brand"):
        reasons.append(
            _reason(
                f"Brand mismatch: page references {page['detected_brand']} but the domain is not official",
                24,
                "content",
            )
        )

    if page.get("external_form_actions", 0) > 0:
        reasons.append(
            _reason(
                "Form submission points to an external domain",
                18,
                "content",
            )
        )

    if not infrastructure.get("https"):
        reasons.append(
            _reason(
                "The page is not using HTTPS",
                14,
                "infrastructure",
            )
        )

    ssl_certificate = infrastructure.get("ssl_certificate", {})
    if ssl_certificate.get("checked") and not ssl_certificate.get("valid", True):
        reasons.append(
            _reason(
                "TLS certificate could not be validated",
                16,
                "infrastructure",
            )
        )

    if reputation.get("source_count", 0) > 0:
        source_count = int(reputation.get("source_count", 0))
        reasons.append(
            _reason(
                f"Matched {source_count} threat-intelligence source{'s' if source_count != 1 else ''}",
                min(30, 12 + source_count * 6),
                "reputation",
            )
        )

    urgency_tokens = [
        str(item["token"])
        for item in (text_terms or [])
        if any(token in str(item["token"]).lower() for token in ("urgent", "verify", "account", "login", "password"))
    ]
    if urgency_tokens:
        reasons.append(
            _reason(
                f"Page language suggests urgency or credential collection ({', '.join(urgency_tokens[:3])})",
                12,
                "text",
            )
        )

    if not reasons:
        dominant = max(
            [
                ("URL structure looks suspicious", url_model_score, "url"),
                ("Page content looks suspicious", content_score, "content"),
                ("Infrastructure signals look suspicious", infrastructure_score, "infrastructure"),
                ("Threat-intelligence signals look suspicious", reputation_score, "reputation"),
            ],
            key=lambda item: item[1],
        )
        reasons.append(_reason(dominant[0], max(8, dominant[1] // 4), dominant[2]))

    reasons.sort(key=lambda item: int(item["impact"]), reverse=True)
    ordered = reasons[:4]

    return {
        "headline": f"Risk: {severity} ({score}%)",
        "severity": severity,
        "reasons": ordered,
        "summary_lines": [item["message"] for item in ordered],
    }


def severity_label(score: int) -> str:
    if score <= 29:
        return "LOW"
    if score <= 59:
        return "MEDIUM"
    if score <= 79:
        return "HIGH"
    return "CRITICAL"


def _reason(message: str, impact: int, category: str) -> dict[str, Any]:
    return {
        "message": message,
        "impact": int(impact),
        "category": category,
    }
