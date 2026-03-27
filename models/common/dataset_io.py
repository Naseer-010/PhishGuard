"""Helpers for reading and writing model datasets."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def read_rows(path: str | Path) -> list[dict[str, Any]]:
    dataset_path = Path(path)
    suffix = dataset_path.suffix.lower()

    if suffix == ".csv":
        with dataset_path.open("r", encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    if suffix == ".json":
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError(f"Expected a list in {dataset_path}")
        return [dict(item) for item in payload]

    if suffix == ".jsonl":
        rows: list[dict[str, Any]] = []
        with dataset_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(dict(json.loads(line)))
        return rows

    raise ValueError(f"Unsupported dataset format: {dataset_path}")


def write_rows(path: str | Path, rows: list[dict[str, Any]]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = output_path.suffix.lower()

    if suffix == ".csv":
        fieldnames: list[str] = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return

    if suffix == ".json":
        output_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return

    if suffix == ".jsonl":
        with output_path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=True))
                handle.write("\n")
        return

    raise ValueError(f"Unsupported dataset format: {output_path}")
