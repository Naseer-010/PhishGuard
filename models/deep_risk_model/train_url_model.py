"""Train URL random forest model using data/phishing.csv."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.deep_risk_model.url_feature_extractor import FEATURE_COLUMNS

DATASET_PATH = ROOT / "data" / "phishing.csv"
ARTIFACT_DIR = ROOT / "models" / "deep_risk_model" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "url_rf.joblib"
METRICS_PATH = ARTIFACT_DIR / "metrics.json"


def train() -> dict:
    df = pd.read_csv(DATASET_PATH)

    x = df[FEATURE_COLUMNS].values
    y_raw = df["class"].values
    # class -1 = phishing, class 1 = legitimate
    y = np.where(y_raw == -1, 1, 0)

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=24,
        min_samples_split=4,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred)), 4),
        "train_size": int(len(x_train)),
        "test_size": int(len(x_test)),
        "feature_columns": FEATURE_COLUMNS,
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    return metrics


if __name__ == "__main__":
    result = train()
    print(json.dumps(result, indent=2))
