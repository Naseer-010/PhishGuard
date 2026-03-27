"""Train a TF-IDF text classifier for the quick phishing model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.text_models import train_tfidf_text_classifier


ARTIFACT_DIR = ROOT / "models" / "quick_content_model" / "artifacts"
TEXT_MODEL_PATH = ARTIFACT_DIR / "quick_tfidf_text.joblib"
TEXT_METRICS_PATH = ARTIFACT_DIR / "quick_tfidf_text_metrics.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the quick TF-IDF phishing text model")
    parser.add_argument("--dataset", required=True, help="CSV/JSON/JSONL dataset with text and label columns")
    parser.add_argument("--text-column", default="text", help="Column containing page text")
    parser.add_argument("--label-column", default="label", help="Column containing binary labels")
    parser.add_argument("--group-column", default="domain_group", help="Optional grouping column for holdout splits")
    parser.add_argument("--max-features", type=int, default=20000, help="Maximum TF-IDF vocabulary size")
    args = parser.parse_args()

    metrics = train_tfidf_text_classifier(
        dataset_path=args.dataset,
        model_path=TEXT_MODEL_PATH,
        metrics_path=TEXT_METRICS_PATH,
        text_column=args.text_column,
        label_column=args.label_column,
        group_column=args.group_column,
        max_features=args.max_features,
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
