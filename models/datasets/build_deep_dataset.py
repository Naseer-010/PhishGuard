"""Build a trainable deep-model feature dataset from a manifest."""

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
from models.datasets.manifest import load_deep_manifest
from models.features.deep_features import (
    build_deep_feature_row,
    build_deep_feature_row_from_snapshot,
    collect_infrastructure_snapshot,
)
from models.features.page_analysis import analyze_html, load_html
from models.features.quick_features import build_quick_feature_dict
from models.reputation.providers import ReputationRegistry


def build_dataset(manifest_path: str | Path, output_path: str | Path) -> list[dict[str, object]]:
    manifest_file = Path(manifest_path)
    out_file = Path(output_path)

    # FIX 1: Provide clear error if manifest is missing
    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest not found at: {manifest_file}")

    # FIX 2: Create processed directory automatically
    out_file.parent.mkdir(parents=True, exist_ok=True)

    samples = load_deep_manifest(manifest_file)
    registry = ReputationRegistry()
    rows: list[dict[str, object]] = []
    
    # Define absolute path to HTML directory
    HTML_DIR = ROOT / "data" / "raw" / "html"

    for sample in samples:
        if not sample.html_path:
            continue

        # FIX 3: Force absolute path resolution
        filename = Path(sample.html_path).name
        html_file_path = HTML_DIR / filename

        if not html_file_path.exists():
            print(f"Warning: HTML file missing at {html_file_path}, skipping...")
            continue

        try:
            # Load HTML using the corrected absolute path
            html = load_html(str(html_file_path))
            page = analyze_html(
                url=sample.url,
                html=html,
                final_url=sample.final_url or sample.url,
                status_code=sample.status_code,
                redirect_count=sample.redirect_count,
                fetched=True,
            )
            quick_features = build_quick_feature_dict(sample.final_url or sample.url, page)

            if sample.network_path:
                row = build_deep_feature_row_from_snapshot(
                    sample_id=sample.sample_id,
                    url=sample.url,
                    label=sample.label,
                    label_source=sample.label_source,
                    collected_at=sample.collected_at,
                    final_url=sample.final_url or sample.url,
                    quick_features=quick_features,
                    network_path=sample.network_path,
                )
            else:
                infrastructure = collect_infrastructure_snapshot(sample.final_url or sample.url)
                reputation = registry.lookup(sample.final_url or sample.url).asdict()
                row = build_deep_feature_row(
                    sample_id=sample.sample_id,
                    url=sample.url,
                    label=sample.label,
                    label_source=sample.label_source,
                    collected_at=sample.collected_at,
                    final_url=sample.final_url or sample.url,
                    quick_features=quick_features,
                    infrastructure=infrastructure,
                    reputation=reputation,
                )

            rows.append(row)
            
        except Exception as e:
            print(f"Warning: Failed to extract deep features for {sample.url}. Error: {e}")
            continue

    if not rows:
        raise ValueError("No valid rows were processed. Check your manifest and HTML files.")

    write_rows(out_file, rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Build deep model feature dataset from a manifest")
    parser.add_argument(
        "--manifest",
        default=str(MANIFEST_DIR / "deep_samples.csv"),
        help="CSV/JSON/JSONL manifest with html_path, labels, and optional network_path",
    )
    parser.add_argument(
        "--output",
        default=str(PROCESSED_DIR / "deep_features.csv"),
        help="Output dataset path (.csv/.json/.jsonl)",
    )
    args = parser.parse_args()

    try:
        rows = build_dataset(args.manifest, args.output)
        print(json.dumps({"rows_written": len(rows), "output_path": args.output}, indent=2))
    except Exception as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
