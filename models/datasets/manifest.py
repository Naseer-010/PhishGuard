"""Manifest readers for quick and deep phishing datasets."""

from __future__ import annotations

from pathlib import Path

from models.common.dataset_io import read_rows
from models.common.schemas import DeepSample, QuickSample


def load_quick_manifest(path: str | Path) -> list[QuickSample]:
    manifest_path = Path(path)
    rows = read_rows(manifest_path)
    return [QuickSample.from_row(row, base_dir=manifest_path.parent) for row in rows]


def load_deep_manifest(path: str | Path) -> list[DeepSample]:
    manifest_path = Path(path)
    rows = read_rows(manifest_path)
    return [DeepSample.from_row(row, base_dir=manifest_path.parent) for row in rows]
