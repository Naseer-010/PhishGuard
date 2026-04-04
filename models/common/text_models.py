"""Reusable text classifiers for phishing content understanding."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from models.common.dataset_io import read_rows
from models.common.model_utils import binary_metrics, split_dataframe


@dataclass(slots=True)
class TextExplanation:
    token: str
    contribution: float


class TfidfTextModel:
    """Inference helper for a TF-IDF + logistic regression classifier."""

    def __init__(self, model_path: str | Path, *, max_characters: int = 12000):
        self.model_path = Path(model_path)
        self.max_characters = max_characters
        self.pipeline = joblib.load(self.model_path) if self.model_path.exists() else None
        self._score_cache: dict[str, int] = {}
        self._explain_cache: dict[tuple[str, int], list[dict[str, float | str]]] = {}

    @property
    def available(self) -> bool:
        return self.pipeline is not None

    def predict_score(self, text: str) -> int | None:
        scores = self.predict_scores([text])
        return scores[0] if scores else None

    def predict_scores(self, texts: list[str]) -> list[int | None]:
        if self.pipeline is None:
            return [None for _ in texts]

        normalized = [self._normalize_text(text) for text in texts]
        missing = [text for text in normalized if text not in self._score_cache]
        if missing:
            unique_missing = list(dict.fromkeys(missing))
            probabilities = self.pipeline.predict_proba(unique_missing)[:, 1]
            for text, probability in zip(unique_missing, probabilities):
                self._score_cache[text] = int(round(float(probability) * 100))
        return [self._score_cache[text] for text in normalized]

    def explain_text(self, text: str, top_k: int = 5) -> list[dict[str, float | str]]:
        if self.pipeline is None:
            return []
        normalized = self._normalize_text(text)
        cache_key = (normalized, top_k)
        if cache_key in self._explain_cache:
            return self._explain_cache[cache_key]

        vectorizer = self.pipeline.named_steps["tfidf"]
        classifier = self.pipeline.named_steps["classifier"]
        feature_names = vectorizer.get_feature_names_out()
        row = vectorizer.transform([normalized])

        if row.nnz == 0:
            return []

        contributions: list[TextExplanation] = []
        for index, value in zip(row.indices, row.data):
            contribution = float(value * classifier.coef_[0][index])
            if contribution > 0:
                contributions.append(TextExplanation(token=str(feature_names[index]), contribution=contribution))

        contributions.sort(key=lambda item: item.contribution, reverse=True)
        explanations = [
            {"token": item.token, "contribution": round(item.contribution, 6)}
            for item in contributions[:top_k]
        ]
        self._explain_cache[cache_key] = explanations
        return explanations

    def _normalize_text(self, text: str) -> str:
        return " ".join(text.split())[: self.max_characters]


class DistilBertTextModel:
    """Optional DistilBERT classifier wrapper."""

    def __init__(
        self,
        model_dir: str | Path,
        *,
        max_length: int = 256,
        max_characters: int = 6000,
    ):
        self.model_dir = Path(model_dir)
        self.max_length = max_length
        self.max_characters = max_characters
        self._loaded = False
        self._tokenizer = None
        self._model = None
        self._torch = None
        self._device = None
        self._score_cache: dict[str, int] = {}

    @property
    def available(self) -> bool:
        if not self.model_dir.exists():
            return False
        return self._load()

    def predict_score(self, text: str) -> int | None:
        scores = self.predict_scores([text])
        return scores[0] if scores else None

    def predict_scores(self, texts: list[str], batch_size: int = 8) -> list[int | None]:
        if not self._load():
            return [None for _ in texts]

        normalized = [self._normalize_text(text) for text in texts]
        missing = [text for text in normalized if text not in self._score_cache]
        if missing:
            unique_missing = list(dict.fromkeys(missing))
            for start in range(0, len(unique_missing), batch_size):
                batch = unique_missing[start:start + batch_size]
                encoded = self._tokenizer(
                    batch,
                    truncation=True,
                    padding=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                )
                encoded = {key: value.to(self._device) for key, value in encoded.items()}
                with self._torch.no_grad():
                    logits = self._model(**encoded).logits
                    probabilities = self._torch.softmax(logits, dim=-1)[:, 1]
                for text, probability in zip(batch, probabilities):
                    self._score_cache[text] = int(round(float(probability.item()) * 100))
        return [self._score_cache[text] for text in normalized]

    def _load(self) -> bool:
        if self._loaded:
            return self._model is not None

        self._loaded = True
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError:
            return False

        try:
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(self.model_dir)
            self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self._model.to(self._device)
            self._model.eval()
            self._torch = torch
            return True
        except Exception:
            self._tokenizer = None
            self._model = None
            self._torch = None
            self._device = None
            return False

    def _normalize_text(self, text: str) -> str:
        return " ".join(text.split())[: self.max_characters]


def train_tfidf_text_classifier(
    dataset_path: str | Path,
    model_path: str | Path,
    metrics_path: str | Path,
    *,
    text_column: str = "text",
    label_column: str = "label",
    group_column: str = "domain_group",
    max_features: int = 20000,
) -> dict[str, Any]:
    rows = read_rows(dataset_path)
    if len(rows) < 10:
        raise ValueError("Need at least 10 labeled text rows to train a TF-IDF classifier")

    frame = pd.DataFrame(rows)
    if text_column not in frame or label_column not in frame:
        raise ValueError(f"Dataset must contain '{text_column}' and '{label_column}' columns")

    frame[text_column] = frame[text_column].fillna("").astype(str)
    frame[label_column] = frame[label_column].astype(int)

    train_frame, test_frame = split_dataframe(frame, label_column=label_column, group_column=group_column if group_column in frame else None)
    if test_frame.empty:
        raise ValueError("Need enough text samples to create a held-out test split")

    pipeline = Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=max_features,
                    lowercase=True,
                    strip_accents="unicode",
                    sublinear_tf=True,
                ),
            ),
            ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=42)),
        ]
    )
    pipeline.fit(train_frame[text_column], train_frame[label_column])

    y_pred = pipeline.predict(test_frame[text_column])
    y_score = pipeline.predict_proba(test_frame[text_column])[:, 1]

    metrics = binary_metrics(test_frame[label_column], y_pred, y_score)
    metrics.update(
        {
            "train_size": int(len(train_frame)),
            "test_size": int(len(test_frame)),
            "model_type": "tfidf_logistic_regression",
            "text_column": text_column,
            "max_features": max_features,
        }
    )

    model_path = Path(model_path)
    metrics_path = Path(metrics_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def train_distilbert_text_classifier(
    dataset_path: str | Path,
    model_dir: str | Path,
    metrics_path: str | Path,
    *,
    text_column: str = "text",
    label_column: str = "label",
    group_column: str = "domain_group",
    base_model: str = "distilbert-base-uncased",
    epochs: int = 2,
    batch_size: int = 8,
    learning_rate: float = 2e-5,
) -> dict[str, Any]:
    try:
        import torch
        from torch.utils.data import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise ImportError(
            "DistilBERT training requires 'transformers', 'torch', and their runtime dependencies"
        ) from exc

    rows = read_rows(dataset_path)
    if len(rows) < 10:
        raise ValueError("Need at least 10 labeled text rows to train DistilBERT")

    frame = pd.DataFrame(rows)
    if text_column not in frame or label_column not in frame:
        raise ValueError(f"Dataset must contain '{text_column}' and '{label_column}' columns")

    frame[text_column] = frame[text_column].fillna("").astype(str)
    frame[label_column] = frame[label_column].astype(int)
    train_frame, test_frame = split_dataframe(frame, label_column=label_column, group_column=group_column if group_column in frame else None)
    if test_frame.empty:
        raise ValueError("Need enough text samples to create a held-out test split")

    tokenizer = AutoTokenizer.from_pretrained(base_model)

    class TextDataset(Dataset):
        def __init__(self, texts: list[str], labels: list[int]):
            self.texts = texts
            self.labels = labels

        def __len__(self) -> int:
            return len(self.texts)

        def __getitem__(self, index: int) -> dict[str, Any]:
            encoded = tokenizer(
                self.texts[index],
                truncation=True,
                padding="max_length",
                max_length=256,
                return_tensors="pt",
            )
            item = {key: value.squeeze(0) for key, value in encoded.items()}
            item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
            return item

    train_dataset = TextDataset(train_frame[text_column].tolist(), train_frame[label_column].tolist())
    test_dataset = TextDataset(test_frame[text_column].tolist(), test_frame[label_column].tolist())

    model = AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2)
    output_dir = Path(model_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    def compute_metrics(pred) -> dict[str, float]:
        predictions = np.argmax(pred.predictions, axis=-1)
        probabilities = np.exp(pred.predictions) / np.sum(np.exp(pred.predictions), axis=-1, keepdims=True)
        return binary_metrics(pred.label_ids, predictions, probabilities[:, 1])

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(output_dir / "runs"),
            learning_rate=learning_rate,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            num_train_epochs=epochs,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            logging_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1_score",
            report_to=[],
        ),
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        tokenizer=tokenizer,
        compute_metrics=compute_metrics,
    )
    trainer.train()
    metrics = trainer.evaluate()
    metrics["train_size"] = int(len(train_frame))
    metrics["test_size"] = int(len(test_frame))
    metrics["model_type"] = "distilbert"
    metrics["base_model"] = base_model

    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    Path(metrics_path).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics
