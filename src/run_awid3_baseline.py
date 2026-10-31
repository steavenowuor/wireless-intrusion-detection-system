"""Run the explicitly exploratory, stratified single-capture AWID3 baseline."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)

from .train_model import train_model

DEFAULT_DATA = Path(__file__).resolve().parents[1] / "data" / "awid3_deauth_capture_sequence_windows_v2.csv"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "models" / "awid3_deauth_baseline_20261031"
LABEL_COLUMN = "window_label"
# Curated numeric summaries that are not label-, provenance-, identifier-, or time-derived.
FEATURE_COLUMNS = [
    "packet_count",
    "management_frame_count",
    "retry_frame_count",
    "retry_frame_fraction",
    "frame_len_mean",
    "frame_len_max",
    "signal_dbm_mean",
    "signal_dbm_min",
    "unique_transmitter_count",
]
FORBIDDEN_FEATURES = {
    "deauth_frame_count", "deauth_frames_per_second", "deauth_frame_fraction",
    "mixed_window", "capture_id", "source_files", "window_start_epoch",
    "source_time_epoch_first", "source_time_epoch_last", "source_time_epoch_min",
    "source_time_epoch_max", "source_frame_number_first", "source_frame_number_last",
    "source_labels", "source_label_counts", "window_label", "Label",
}


def run(data_path: Path, output_dir: Path) -> dict:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"Refusing to overwrite non-empty experiment directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    frame = pd.read_csv(data_path)
    required = set(FEATURE_COLUMNS + [LABEL_COLUMN, "mixed_window"])
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Prepared data is missing expected columns: {missing}")
    labels = frame[LABEL_COLUMN].astype(str)
    counts = labels.value_counts().to_dict()
    if set(counts) != {"Normal", "Deauth"} or counts != {"Normal": 424, "Deauth": 180}:
        raise ValueError(f"Unexpected labels/counts for audited dataset: {counts}")
    if not frame.loc[labels.eq("Deauth"), "mixed_window"].astype(bool).all():
        raise ValueError("Expected every Deauth-labelled window to be mixed in this audited dataset")
    if FORBIDDEN_FEATURES.intersection(FEATURE_COLUMNS):
        raise AssertionError("A label-derived or metadata field was included as a feature")
    features = frame[FEATURE_COLUMNS]
    if not all(pd.api.types.is_numeric_dtype(features[c]) for c in FEATURE_COLUMNS):
        raise ValueError("All curated model inputs must be numeric")
    values = features.to_numpy(dtype="float64")
    if not np.isfinite(values).all():
        raise ValueError("Curated features contain missing or non-finite values")

    # Deliberately omit group/time arguments: the existing trainer performs a
    # reproducible stratified random holdout. This is within-capture exploration.
    result = train_model(
        frame[FEATURE_COLUMNS + [LABEL_COLUMN]],
        label_column=LABEL_COLUMN,
        model_path=output_dir / "decision_tree.joblib",
        report_dir=output_dir,
        test_size=0.20,
        deauth_labels=["Deauth"],
        input_csv_path=data_path,
        data_manifest=json.loads(data_path.with_suffix(data_path.suffix + ".manifest.json").read_text(encoding="utf-8")),
    )
    predictions_frame = pd.read_csv(output_dir / "test_predictions.csv")
    y_test = predictions_frame["binary_label"].to_numpy(dtype=int)
    train_counts = result["train_binary_class_counts"]
    majority_class = 0 if train_counts["normal"] >= train_counts["malicious"] else 1
    baseline_predictions = np.full(len(y_test), majority_class, dtype=int)
    baseline = {
        "method": "always predict the majority class in the training partition",
        "predicted_class": "Normal" if majority_class == 0 else "Deauth",
        "accuracy": float(accuracy_score(y_test, baseline_predictions)),
        "precision": float(precision_score(y_test, baseline_predictions, zero_division=0)),
        "recall": float(recall_score(y_test, baseline_predictions, zero_division=0)),
        "f1_score": float(f1_score(y_test, baseline_predictions, zero_division=0)),
        "confusion_matrix_labels": ["Normal", "Deauth"],
        "confusion_matrix": confusion_matrix(y_test, baseline_predictions, labels=[0, 1]).tolist(),
        "test_rows": len(y_test),
    }
    (output_dir / "majority_baseline.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    (output_dir / "feature_columns.json").write_text(json.dumps(FEATURE_COLUMNS, indent=2), encoding="utf-8")
    experiment = {
        "dataset": str(data_path.resolve()),
        "dataset_rows": len(frame),
        "dataset_window_label_counts": counts,
        "source_sequence_confidence": "strongly corroborated ordered sequence; original pcap identity unestablished",
        "independent_capture_validation": False,
        "split_interpretation": "Exploratory stratified random holdout within one capture sequence; nearby windows may be correlated.",
        "random_seed": 42,
        "requested_test_fraction": 0.20,
        "feature_columns": FEATURE_COLUMNS,
        "excluded_target_derived_and_metadata_columns": sorted(FORBIDDEN_FEATURES),
        "model": "scikit-learn DecisionTreeClassifier",
        "metrics_file": "metrics.json",
        "predictions_file": "test_predictions.csv",
        "majority_baseline_file": "majority_baseline.json",
    }
    (output_dir / "experiment_manifest.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
    metrics_path = output_dir / "metrics.json"
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["evaluation_scope"] = experiment["split_interpretation"]
    metrics["independent_capture_validation"] = False
    metrics["majority_class_baseline"] = baseline
    metrics["feature_columns"] = FEATURE_COLUMNS
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    metrics = run(args.data, args.output_dir)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
