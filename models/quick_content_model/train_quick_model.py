"""Train the lightweight quick phishing model from labeled HTML snapshots."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.dataset_io import read_rows
from models.common.model_utils import binary_metrics, fit_frame_columns, split_dataframe
from models.common.paths import MANIFEST_DIR, PROCESSED_DIR
from models.datasets.build_quick_dataset import build_dataset
from models.features.quick_features import QUICK_FEATURE_COLUMNS


ARTIFACT_DIR = ROOT / "models" / "quick_content_model" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "quick_model.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"
BROWSER_EXPORT_PATH = ARTIFACT_DIR / "quick_model_browser.json"
DEFAULT_MANIFEST = MANIFEST_DIR / "quick_samples.csv"
DEFAULT_DATASET = PROCESSED_DIR / "quick_features.csv"


def train(manifest_path: str | Path = DEFAULT_MANIFEST, dataset_path: str | Path = DEFAULT_DATASET) -> dict[str, object]:
    dataset_file = Path(dataset_path)
    if dataset_file.exists():
        rows = read_rows(dataset_file)
    elif Path(manifest_path).exists():
        rows = build_dataset(manifest_path, dataset_file)
    else:
        raise FileNotFoundError(
            "Quick model training data not found. Create data/manifests/quick_samples.csv "
            "with labeled html_path entries first."
        )

    if len(rows) < 10:
        raise ValueError("Need at least 10 labeled samples to train the quick model")

    frame = pd.DataFrame(rows)
    train_frame, test_frame = split_dataframe(frame, label_column="label", group_column="domain_group")
    if test_frame.empty:
        raise ValueError("Need enough distinct samples to create a held-out test split")

    x_train = fit_frame_columns(train_frame, QUICK_FEATURE_COLUMNS)
    y_train = train_frame["label"].astype(int)
    x_test = fit_frame_columns(test_frame, QUICK_FEATURE_COLUMNS)
    y_test = test_frame["label"].astype(int)

    pipeline = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=42)),
        ]
    )
    pipeline.fit(x_train, y_train)

    y_pred = pipeline.predict(x_test)
    y_score = pipeline.predict_proba(x_test)[:, 1]

    classifier = pipeline.named_steps["classifier"]
    scaler = pipeline.named_steps["scaler"]
    coefficients = {}
    for feature_name, coefficient, scale in zip(QUICK_FEATURE_COLUMNS, classifier.coef_[0], scaler.scale_):
        normalized = float(coefficient / scale) if scale else float(coefficient)
        coefficients[feature_name] = round(normalized, 6)

    metrics = binary_metrics(y_test, y_pred, y_score)
    metrics.update(
        {
            "train_size": int(len(train_frame)),
            "test_size": int(len(test_frame)),
            "feature_columns": QUICK_FEATURE_COLUMNS,
            "model_type": "logistic_regression",
            "top_positive_features": sorted(coefficients.items(), key=lambda item: item[1], reverse=True)[:15],
            "top_negative_features": sorted(coefficients.items(), key=lambda item: item[1])[:15],
        }
    )

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    BROWSER_EXPORT_PATH.write_text(
        json.dumps(
            {
                "model_type": "logistic_regression",
                "feature_columns": QUICK_FEATURE_COLUMNS,
                "coefficients": coefficients,
                "intercept": round(float(classifier.intercept_[0]), 6),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the quick phishing model from labeled HTML samples")
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to quick_samples manifest (.csv/.json/.jsonl)",
    )
    parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DATASET),
        help="Optional processed feature dataset path (.csv/.json/.jsonl)",
    )
    args = parser.parse_args()

    result = train(manifest_path=args.manifest, dataset_path=args.dataset)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
