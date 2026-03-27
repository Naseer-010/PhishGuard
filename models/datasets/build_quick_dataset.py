"""Build a trainable quick-model feature dataset from a manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.dataset_io import write_rows
from models.common.paths import MANIFEST_DIR, PROCESSED_DIR
from models.datasets.manifest import load_quick_manifest
from models.features.quick_features import build_quick_feature_row_from_html_path


def build_dataset(manifest_path: str | Path, output_path: str | Path) -> list[dict[str, object]]:
    samples = load_quick_manifest(manifest_path)
    rows: list[dict[str, object]] = []
    for sample in samples:
        if not sample.html_path:
            continue
        rows.append(
            build_quick_feature_row_from_html_path(
                sample_id=sample.sample_id,
                url=sample.url,
                label=sample.label,
                label_source=sample.label_source,
                collected_at=sample.collected_at,
                final_url=sample.final_url or sample.url,
                html_path=sample.html_path,
                status_code=sample.status_code,
                redirect_count=sample.redirect_count,
            )
        )
    write_rows(output_path, rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build quick model feature dataset from a manifest")
    parser.add_argument(
        "--manifest",
        default=str(MANIFEST_DIR / "quick_samples.csv"),
        help="CSV/JSON/JSONL manifest with html_path and labels",
    )
    parser.add_argument(
        "--output",
        default=str(PROCESSED_DIR / "quick_features.csv"),
        help="Output dataset path (.csv/.json/.jsonl)",
    )
    args = parser.parse_args()

    rows = build_dataset(args.manifest, args.output)
    print(json.dumps({"rows_written": len(rows), "output_path": args.output}, indent=2))


if __name__ == "__main__":
    main()
