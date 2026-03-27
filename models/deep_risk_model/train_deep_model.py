"""Train deep phishing submodels and the final meta-model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from models.common.dataset_io import read_rows
from models.common.model_utils import binary_metrics, fit_frame_columns, split_dataframe
from models.common.paths import MANIFEST_DIR, PROCESSED_DIR
from models.datasets.build_deep_dataset import build_dataset
from models.features.deep_features import DEEP_FEATURE_COLUMNS


ARTIFACT_DIR = ROOT / "models" / "deep_risk_model" / "artifacts"
PAGE_MODEL_PATH = ARTIFACT_DIR / "page_rf.joblib"
INFRA_MODEL_PATH = ARTIFACT_DIR / "infra_rf.joblib"
REPUTATION_MODEL_PATH = ARTIFACT_DIR / "reputation_lr.joblib"
META_MODEL_PATH = ARTIFACT_DIR / "meta_lr.joblib"
METRICS_PATH = ARTIFACT_DIR / "deep_metrics.json"
DEFAULT_MANIFEST = MANIFEST_DIR / "deep_samples.csv"
DEFAULT_DATASET = PROCESSED_DIR / "deep_features.csv"

URL_FEATURE_COLUMNS = [column for column in DEEP_FEATURE_COLUMNS if column.startswith("url_feature__")] + [
    "uses_ip_host",
    "url_length",
    "subdomain_depth",
    "has_at_symbol",
    "has_punycode",
    "suspicious_tld",
    "hyphen_count",
    "digit_ratio",
    "path_depth",
    "query_length",
    "is_https",
    "redirect_count",
]

PAGE_FEATURE_COLUMNS = [
    "text_length",
    "visible_word_count",
    "forms_count",
    "password_fields_count",
    "hidden_inputs_count",
    "iframe_count",
    "external_links_count",
    "external_link_ratio",
    "resource_count",
    "external_resource_count",
    "external_resource_ratio",
    "external_form_actions",
    "has_login_form",
    "favicon_host_mismatch",
    "script_obfuscation_signals",
    "threat_keyword_count",
    "threat_keyword_weight",
    "safe_keyword_count",
    "safe_keyword_weight",
    "urgency_keyword_count",
    "credential_keyword_count",
    "financial_keyword_count",
    "brand_keyword_count",
]

INFRA_FEATURE_COLUMNS = [
    "uses_ip_host",
    "has_punycode",
    "suspicious_tld",
    "is_https",
    "redirect_count",
    "dns_resolves",
    "host_is_ip",
    "punycode_domain",
    "suspicious_tld_infra",
    "non_standard_port",
    "tls_checked",
    "tls_valid",
    "tls_days_to_expiry",
    "tls_expiring_soon",
]

REPUTATION_FEATURE_COLUMNS = [
    "reputation_url_hits",
    "reputation_domain_hits",
    "reputation_source_count",
    "reputation_confidence",
]

META_FEATURE_COLUMNS = [
    "url_score",
    "page_score",
    "infra_score",
    "reputation_score",
    "password_fields_count",
    "external_form_actions",
    "script_obfuscation_signals",
    "tls_valid",
    "reputation_source_count",
]


def _fit_submodel(frame: pd.DataFrame, feature_columns: list[str], model) -> object:
    x = fit_frame_columns(frame, feature_columns)
    y = frame["label"].astype(int)
    model.fit(x, y)
    return model


def train(manifest_path: str | Path = DEFAULT_MANIFEST, dataset_path: str | Path = DEFAULT_DATASET) -> dict[str, object]:
    dataset_file = Path(dataset_path)
    if dataset_file.exists():
        rows = read_rows(dataset_file)
    elif Path(manifest_path).exists():
        rows = build_dataset(manifest_path, dataset_file)
    else:
        raise FileNotFoundError(
            "Deep model training data not found. Create data/manifests/deep_samples.csv "
            "with labeled html_path entries first."
        )

    if len(rows) < 20:
        raise ValueError("Need at least 20 labeled samples to train the deep model")

    frame = pd.DataFrame(rows)
    train_frame, test_frame = split_dataframe(frame, label_column="label", group_column="domain_group")
    if test_frame.empty:
        raise ValueError("Need enough distinct samples to create a held-out test split")

    url_model = _fit_submodel(
        train_frame,
        URL_FEATURE_COLUMNS,
        RandomForestClassifier(
            n_estimators=300,
            max_depth=22,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),
    )
    page_model = _fit_submodel(
        train_frame,
        PAGE_FEATURE_COLUMNS,
        RandomForestClassifier(
            n_estimators=250,
            max_depth=18,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),
    )
    infra_model = _fit_submodel(
        train_frame,
        INFRA_FEATURE_COLUMNS,
        RandomForestClassifier(
            n_estimators=220,
            max_depth=14,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ),
    )
    reputation_model = _fit_submodel(
        train_frame,
        REPUTATION_FEATURE_COLUMNS,
        LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
    )

    meta_train = train_frame.copy()
    meta_train["url_score"] = url_model.predict_proba(fit_frame_columns(meta_train, URL_FEATURE_COLUMNS))[:, 1]
    meta_train["page_score"] = page_model.predict_proba(fit_frame_columns(meta_train, PAGE_FEATURE_COLUMNS))[:, 1]
    meta_train["infra_score"] = infra_model.predict_proba(fit_frame_columns(meta_train, INFRA_FEATURE_COLUMNS))[:, 1]
    meta_train["reputation_score"] = reputation_model.predict_proba(
        fit_frame_columns(meta_train, REPUTATION_FEATURE_COLUMNS)
    )[:, 1]

    meta_model = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    meta_model.fit(fit_frame_columns(meta_train, META_FEATURE_COLUMNS), meta_train["label"].astype(int))

    eval_frame = test_frame.copy()
    eval_frame["url_score"] = url_model.predict_proba(fit_frame_columns(eval_frame, URL_FEATURE_COLUMNS))[:, 1]
    eval_frame["page_score"] = page_model.predict_proba(fit_frame_columns(eval_frame, PAGE_FEATURE_COLUMNS))[:, 1]
    eval_frame["infra_score"] = infra_model.predict_proba(fit_frame_columns(eval_frame, INFRA_FEATURE_COLUMNS))[:, 1]
    eval_frame["reputation_score"] = reputation_model.predict_proba(
        fit_frame_columns(eval_frame, REPUTATION_FEATURE_COLUMNS)
    )[:, 1]

    y_true = eval_frame["label"].astype(int)
    y_score = meta_model.predict_proba(fit_frame_columns(eval_frame, META_FEATURE_COLUMNS))[:, 1]
    y_pred = (y_score >= 0.5).astype(int)

    metrics = binary_metrics(y_true, y_pred, y_score)
    metrics.update(
        {
            "train_size": int(len(train_frame)),
            "test_size": int(len(test_frame)),
            "url_feature_count": len(URL_FEATURE_COLUMNS),
            "page_feature_count": len(PAGE_FEATURE_COLUMNS),
            "infra_feature_count": len(INFRA_FEATURE_COLUMNS),
            "reputation_feature_count": len(REPUTATION_FEATURE_COLUMNS),
            "meta_feature_columns": META_FEATURE_COLUMNS,
        }
    )

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(url_model, ARTIFACT_DIR / "url_stack_rf.joblib")
    joblib.dump(page_model, PAGE_MODEL_PATH)
    joblib.dump(infra_model, INFRA_MODEL_PATH)
    joblib.dump(reputation_model, REPUTATION_MODEL_PATH)
    joblib.dump(meta_model, META_MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the deep phishing ensemble from labeled HTML samples")
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to deep_samples manifest (.csv/.json/.jsonl)",
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
