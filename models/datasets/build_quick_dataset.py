"""Build a trainable quick-model feature dataset from a manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Robust ROOT resolution
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.dataset_io import write_rows
from models.common.paths import MANIFEST_DIR, PROCESSED_DIR
from models.datasets.manifest import load_quick_manifest
from models.features.quick_features import build_quick_feature_row_from_html_path


def build_dataset(manifest_path: str | Path, output_path: str | Path) -> list[dict[str, object]]:
    manifest_file = Path(manifest_path)
    out_file = Path(output_path)

    if not manifest_file.exists():
        raise FileNotFoundError(f"Manifest not found at: {manifest_file}")

    out_file.parent.mkdir(parents=True, exist_ok=True)

    samples = load_quick_manifest(manifest_file)
    rows: list[dict[str, object]] = []
    
    # Define the absolute, correct path to the HTML folder
    HTML_DIR = ROOT / "data" / "raw" / "html"
    
    for sample in samples:
        if not sample.html_path:
            continue
            
        # FIX: Extract just the filename (e.g., '12345hash.html') and force 
        # it into the correct absolute directory, bypassing relative path bugs.
        filename = Path(sample.html_path).name
        html_file_path = HTML_DIR / filename
        
        if not html_file_path.exists():
            # Now it will print the EXACT path it tried to check so we can debug if it fails
            print(f"Warning: HTML file missing at {html_file_path}, skipping...")
            continue

        try:
            rows.append(
                build_quick_feature_row_from_html_path(
                    sample_id=sample.sample_id,
                    url=sample.url,
                    label=sample.label,
                    label_source=sample.label_source,
                    collected_at=sample.collected_at,
                    final_url=sample.final_url or sample.url,
                    html_path=str(html_file_path),
                    status_code=sample.status_code,
                    redirect_count=sample.redirect_count,
                )
            )
        except Exception as e:
            print(f"Warning: Failed to extract features for {sample.url}. Error: {e}")
            continue

    if not rows:
        raise ValueError("No valid rows were processed. Check your manifest and HTML files.")

    write_rows(out_file, rows)
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

    try:
        rows = build_dataset(args.manifest, args.output)
        print(json.dumps({"rows_written": len(rows), "output_path": args.output}, indent=2))
    except Exception as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
