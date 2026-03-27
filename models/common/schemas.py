"""Shared schemas for phishing samples and predictions."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _normalize_label(value: str | int | None) -> int:
    if value is None:
        raise ValueError("Missing label")

    if isinstance(value, int):
        if value in {0, 1}:
            return value
        if value == -1:
            return 1
        raise ValueError(f"Unsupported numeric label: {value}")

    text = str(value).strip().lower()
    if text in {"1", "phishing", "malicious", "dangerous", "true", "yes"}:
        return 1
    if text in {"0", "legitimate", "benign", "safe", "false", "no"}:
        return 0
    if text == "-1":
        return 1
    raise ValueError(f"Unsupported label: {value}")


@dataclass(slots=True)
class QuickSample:
    sample_id: str
    url: str
    label: int
    label_source: str = "unknown"
    collected_at: str = ""
    final_url: str = ""
    html_path: str = ""
    status_code: int | None = None
    redirect_count: int = 0

    @classmethod
    def from_row(cls, row: dict[str, Any], base_dir: Path | None = None) -> "QuickSample":
        html_path = str(row.get("html_path", "")).strip()
        if html_path and base_dir is not None:
            candidate = Path(html_path)
            if not candidate.is_absolute():
                html_path = str((base_dir / candidate).resolve())

        status_code_raw = str(row.get("status_code", "")).strip()
        redirect_count_raw = str(row.get("redirect_count", "")).strip()
        return cls(
            sample_id=str(row.get("sample_id") or row.get("id") or row.get("url") or "").strip(),
            url=str(row.get("url") or "").strip(),
            label=_normalize_label(row.get("label")),
            label_source=str(row.get("label_source", "unknown")).strip() or "unknown",
            collected_at=str(row.get("collected_at", "")).strip(),
            final_url=str(row.get("final_url", "")).strip(),
            html_path=html_path,
            status_code=int(status_code_raw) if status_code_raw else None,
            redirect_count=int(redirect_count_raw or 0),
        )

    def asdict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeepSample(QuickSample):
    network_path: str = ""

    @classmethod
    def from_row(cls, row: dict[str, Any], base_dir: Path | None = None) -> "DeepSample":
        quick_sample = QuickSample.from_row(row, base_dir=base_dir)
        network_path = str(row.get("network_path", "")).strip()
        if network_path and base_dir is not None:
            candidate = Path(network_path)
            if not candidate.is_absolute():
                network_path = str((base_dir / candidate).resolve())

        return cls(
            sample_id=quick_sample.sample_id,
            url=quick_sample.url,
            label=quick_sample.label,
            label_source=quick_sample.label_source,
            collected_at=quick_sample.collected_at,
            final_url=quick_sample.final_url,
            html_path=quick_sample.html_path,
            status_code=quick_sample.status_code,
            redirect_count=quick_sample.redirect_count,
            network_path=network_path,
        )


@dataclass(slots=True)
class QuickPrediction:
    url: str
    final_url: str
    risk_score: int
    risk_band: str
    fetched: bool
    model_version: str
    reasons: list[str] = field(default_factory=list)
    features: dict[str, float | int] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def asdict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeepPrediction:
    url: str
    final_url: str
    risk_score: int
    verdict: str
    is_phishing: bool
    model_version: str
    subscores: dict[str, int]
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def asdict(self) -> dict[str, Any]:
        return asdict(self)
