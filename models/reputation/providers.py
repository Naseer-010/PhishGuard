"""Local-feed reputation adapters for phishing URL/domain matches."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from models.common.paths import RAW_DIR


@dataclass(slots=True)
class ReputationMatch:
    url_hits: int
    domain_hits: int
    source_count: int
    confidence: int
    matched_sources: list[str]

    def asdict(self) -> dict[str, int | list[str]]:
        return asdict(self)


class ReputationRegistry:
    """Loads local feed snapshots and performs exact URL/domain lookups."""

    def __init__(self, feed_dir: Path | None = None):
        self.feed_dir = feed_dir or (RAW_DIR / "feeds")
        self._sources: dict[str, tuple[set[str], set[str]]] = {}
        self._loaded = False

    def lookup(self, url: str) -> ReputationMatch:
        self._ensure_loaded()
        normalized_url = self._normalize_url(url)
        host = (urlparse(normalized_url).hostname or "").lower()

        url_hits = 0
        domain_hits = 0
        matched_sources: list[str] = []

        for source, (urls, domains) in self._sources.items():
            matched = False
            if normalized_url in urls:
                url_hits += 1
                matched = True
            if host and host in domains:
                domain_hits += 1
                matched = True
            if matched:
                matched_sources.append(source)

        confidence = min(100, url_hits * 45 + domain_hits * 20 + max(0, len(matched_sources) - 1) * 10)
        return ReputationMatch(
            url_hits=url_hits,
            domain_hits=domain_hits,
            source_count=len(matched_sources),
            confidence=confidence,
            matched_sources=matched_sources,
        )

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.feed_dir.exists():
            return

        for path in sorted(self.feed_dir.iterdir()):
            if path.suffix.lower() not in {".txt", ".csv"}:
                continue
            urls, domains = self._read_feed(path)
            self._sources[path.stem] = (urls, domains)

    def _read_feed(self, path: Path) -> tuple[set[str], set[str]]:
        urls: set[str] = set()
        domains: set[str] = set()

        if path.suffix.lower() == ".txt":
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    candidate = line.strip()
                    self._accumulate(candidate, urls, domains)
            return urls, domains

        with path.open("r", encoding="utf-8", newline="", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            columns = reader.fieldnames or []
            url_column = next((column for column in columns if column.lower() in {"url", "phish_url", "indicator"}), "")
            domain_column = next((column for column in columns if column.lower() in {"domain", "host", "hostname"}), "")
            for row in reader:
                if url_column:
                    self._accumulate(str(row.get(url_column, "")).strip(), urls, domains)
                if domain_column:
                    host = str(row.get(domain_column, "")).strip().lower()
                    if host:
                        domains.add(host)
        return urls, domains

    def _accumulate(self, candidate: str, urls: set[str], domains: set[str]) -> None:
        normalized = self._normalize_url(candidate)
        if not normalized:
            return
        urls.add(normalized)
        host = (urlparse(normalized).hostname or "").lower()
        if host:
            domains.add(host)

    def _normalize_url(self, value: str) -> str:
        candidate = value.strip()
        if not candidate or candidate.startswith("#"):
            return ""
        if not candidate.startswith(("http://", "https://")):
            candidate = f"http://{candidate}"
        parsed = urlparse(candidate)
        if not parsed.hostname:
            return ""
        path = parsed.path or "/"
        if parsed.query:
            return f"{parsed.scheme}://{parsed.hostname}{path}?{parsed.query}"
        return f"{parsed.scheme}://{parsed.hostname}{path}"
