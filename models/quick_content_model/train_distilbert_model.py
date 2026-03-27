"""Train a DistilBERT text classifier for the quick phishing model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.text_models import train_distilbert_text_classifier


ARTIFACT_DIR = ROOT / "models" / "quick_content_model" / "artifacts"
MODEL_DIR = ARTIFACT_DIR / "quick_distilbert"
METRICS_PATH = ARTIFACT_DIR / "quick_distilbert_metrics.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the quick DistilBERT phishing text model")
    parser.add_argument("--dataset", required=True, help="CSV/JSON/JSONL dataset with text and label columns")
    parser.add_argument("--text-column", default="text", help="Column containing page text")
    parser.add_argument("--label-column", default="label", help="Column containing binary labels")
    parser.add_argument("--group-column", default="domain_group", help="Optional grouping column for holdout splits")
    parser.add_argument("--epochs", type=int, default=2, help="Number of fine-tuning epochs")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-5, help="Learning rate")
    args = parser.parse_args()

    metrics = train_distilbert_text_classifier(
        dataset_path=args.dataset,
        model_dir=MODEL_DIR,
        metrics_path=METRICS_PATH,
        text_column=args.text_column,
        label_column=args.label_column,
        group_column=args.group_column,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
