"""Reusable helpers for training and scoring models."""

from __future__ import annotations

from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, train_test_split


def split_dataframe(
    frame: pd.DataFrame,
    label_column: str,
    group_column: str | None = None,
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if len(frame) < 4:
        return frame.copy(), frame.iloc[0:0].copy()

    if group_column and group_column in frame and frame[group_column].nunique() > 1:
        splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
        groups = frame[group_column]
        train_idx, test_idx = next(splitter.split(frame, frame[label_column], groups))
        return frame.iloc[train_idx].copy(), frame.iloc[test_idx].copy()

    train_frame, test_frame = train_test_split(
        frame,
        test_size=test_size,
        random_state=random_state,
        stratify=frame[label_column],
    )
    return train_frame.copy(), test_frame.copy()


def binary_metrics(y_true: Iterable[int], y_pred: Iterable[int], y_score: Iterable[float] | None = None) -> dict[str, float]:
    y_true_arr = np.array(list(y_true))
    y_pred_arr = np.array(list(y_pred))
    metrics = {
        "accuracy": round(float(accuracy_score(y_true_arr, y_pred_arr)), 4),
        "precision": round(float(precision_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true_arr, y_pred_arr, zero_division=0)), 4),
    }
    if y_score is not None and len(np.unique(y_true_arr)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true_arr, np.array(list(y_score)))), 4)
    return metrics


def fit_frame_columns(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    missing = [column for column in columns if column not in frame]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return frame[columns].fillna(0.0)
