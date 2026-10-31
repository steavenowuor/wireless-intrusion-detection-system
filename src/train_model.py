"""Reproducible Decision Tree training for already-tabular offline data."""
from pathlib import Path
import argparse
import math
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier

from .config import MODEL_DIR, MODEL_PATH, RANDOM_SEED, DEFAULT_LABEL_COLUMN
from .data_loader import load_csv, split_features_and_labels
from .feature_extraction import remove_obvious_leakage
from .evaluate_model import evaluate_model


def build_pipeline(features: pd.DataFrame) -> Pipeline:
    """Build preprocessing and classifier together so transforms fit on train only."""
    numeric = features.select_dtypes(include=["number", "bool"]).columns.tolist()
    categorical = [column for column in features.columns if column not in numeric]
    transformers = []
    if numeric:
        transformers.append(("numeric", SimpleImputer(strategy="median", keep_empty_features=True), numeric))
    if categorical:
        categorical_steps = Pipeline([
            # Constant fill also handles categorical columns that are entirely empty.
            ("imputer", SimpleImputer(strategy="constant", fill_value="__missing__",
                                       keep_empty_features=True)),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ])
        transformers.append(("categorical", categorical_steps, categorical))
    preprocessing = ColumnTransformer(transformers=transformers, remainder="drop")
    return Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", DecisionTreeClassifier(random_state=RANDOM_SEED)),
    ])


def _chronological_split(frame: pd.DataFrame, time_column: str, test_size: float,
                         gap_seconds: float) -> tuple[np.ndarray, np.ndarray]:
    """Split ordered windows by time and purge a small boundary gap."""
    if time_column not in frame.columns:
        raise ValueError(f"Time column '{time_column}' was not found")
    times = pd.to_numeric(frame[time_column], errors="coerce")
    if times.isna().any() or not np.isfinite(times.to_numpy(dtype=float)).all():
        raise ValueError(f"Time column '{time_column}' contains missing or invalid values")
    unique_times = np.sort(times.unique())
    if len(unique_times) < 3:
        raise ValueError("Chronological split needs at least three distinct time windows")
    split_position = int(np.floor((1.0 - test_size) * len(unique_times)))
    split_position = min(max(split_position, 1), len(unique_times) - 1)
    split_time = float(unique_times[split_position])
    train_mask = times < (split_time - gap_seconds)
    test_mask = times >= split_time
    train_idx = np.flatnonzero(train_mask.to_numpy())
    test_idx = np.flatnonzero(test_mask.to_numpy())
    if not len(train_idx) or not len(test_idx):
        raise ValueError("Chronological split produced an empty partition; adjust test_size or time gap")
    return train_idx, test_idx


def train_model(frame: pd.DataFrame, label_column: str = DEFAULT_LABEL_COLUMN,
                model_path: str | Path = MODEL_PATH, report_dir: str | Path | None = None,
                test_size: float = 0.2, group_column: str | None = None,
                deauth_labels: list[str] | None = None,
                time_column: str | None = None,
                temporal_gap_seconds: float = 1.0,
                data_manifest: dict | None = None,
                input_csv_path: str | Path | None = None) -> dict:
    """Split, fit, evaluate and save a model package from a labeled DataFrame.

    The package includes the full fitted preprocessing/model pipeline, feature
    names, dropped identifier names, and original labels for the held-out rows.
    """
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1")
    features, labels, original_labels = split_features_and_labels(frame, label_column)
    groups = None
    if temporal_gap_seconds < 0 or not math.isfinite(temporal_gap_seconds):
        raise ValueError("temporal_gap_seconds must be finite and non-negative")
    times = None
    if time_column is not None:
        if time_column in {label_column, group_column}:
            raise ValueError("Time column must be separate from the label and group columns")
        if time_column not in frame.columns:
            raise ValueError(f"Time column '{time_column}' was not found")
        times = pd.to_numeric(frame[time_column], errors="coerce")
        if times.isna().any() or not np.isfinite(times.to_numpy(dtype=float)).all():
            raise ValueError(f"Time column '{time_column}' contains missing or invalid values")
    if group_column is not None:
        if group_column == label_column or group_column not in frame.columns:
            raise ValueError(f"Group column '{group_column}' must name a non-label dataset column")
        groups = frame[group_column].copy()
        if groups.isna().any():
            raise ValueError("Group column contains missing values")
        features = features.drop(columns=[group_column])
    features, dropped = remove_obvious_leakage(features)
    if labels.nunique() != 2:
        raise ValueError("Training data must contain both binary classes (0=normal, 1=malicious)")
    if labels.value_counts().min() < 2:
        raise ValueError("Each class needs at least two rows for a stratified train/test split")
    if math.ceil(test_size * len(frame)) < labels.nunique():
        raise ValueError("Test split is too small to contain both classes; provide more rows or increase test_size")
    original_text = original_labels.astype(str).str.strip()
    original_counts = original_text.value_counts()
    # Keep whole capture/session groups together when such a column is supplied.
    if groups is not None:
        if groups.nunique() > 1:
            splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=RANDOM_SEED)
            train_idx, test_idx = next(splitter.split(features, labels, groups=groups))
            split_method = f"group shuffle by {group_column}"
        elif times is not None:
            train_idx, test_idx = _chronological_split(frame, time_column, test_size,
                                                       temporal_gap_seconds)
            split_method = (f"chronological holdout by {time_column} with "
                            f"{temporal_gap_seconds:g}s purge; within-capture evaluation")
        else:
            raise ValueError("Only one capture group is available; provide a time_column for a "
                             "documented within-capture chronological holdout")
    elif times is not None:
        train_idx, test_idx = _chronological_split(frame, time_column, test_size,
                                                   temporal_gap_seconds)
        split_method = (f"chronological holdout by {time_column} with "
                        f"{temporal_gap_seconds:g}s purge; capture identity unavailable")
    else:
        # Prefer stratifying the original attack classes when each can appear in both partitions.
        stratify = original_text if original_counts.min() >= 2 and math.ceil(test_size * len(frame)) >= len(original_counts) else labels
        train_idx, test_idx = train_test_split(
            np.arange(len(frame)), test_size=test_size, random_state=RANDOM_SEED,
            stratify=stratify,
        )
        split_method = "stratified by original label" if stratify is original_text else "stratified binary row split"
    if labels.iloc[train_idx].nunique() != 2 or labels.iloc[test_idx].nunique() != 2:
        raise ValueError("Selected split does not contain both binary classes in train and test; choose a better group column or test_size")
    x_train, x_test = features.iloc[train_idx], features.iloc[test_idx]
    y_train, y_test = labels.iloc[train_idx], labels.iloc[test_idx]
    original_train, original_test = original_text.iloc[train_idx], original_text.iloc[test_idx]
    metadata_columns = [column for column in ("capture_id", "window_start_epoch", "source_files",
                                               "source_labels", "source_label_counts")
                        if column in frame.columns]
    purged_rows = len(frame) - len(train_idx) - len(test_idx)
    pipeline = build_pipeline(x_train)
    pipeline.fit(x_train, y_train)
    predictions = pipeline.predict(x_test)
    attack_type_pipeline = build_pipeline(x_train)
    attack_type_pipeline.fit(x_train, original_train)
    attack_type_predictions = attack_type_pipeline.predict(x_test)

    if deauth_labels is None:
        selected_deauth = {value.lower() for value in original_text.unique()
                           if "deauth" in value.lower().replace("_", "").replace("-", "")}
    else:
        selected_deauth = {str(value).strip().lower() for value in deauth_labels}
        available_labels = {value.lower() for value in original_text.unique()}
        unknown_deauth = selected_deauth - available_labels
        if unknown_deauth:
            raise ValueError("Selected deauthentication label(s) not found in dataset: "
                             + ", ".join(sorted(unknown_deauth)))
    deauth_true = original_test.str.lower().isin(selected_deauth).astype("int64")
    deauth_pred = pd.Series(attack_type_predictions).str.lower().isin(selected_deauth).astype("int64")
    package_path = Path(model_path)
    package_path.parent.mkdir(parents=True, exist_ok=True)
    package = {
        "pipeline": pipeline,
        "attack_type_pipeline": attack_type_pipeline,
        "attack_type_labels": sorted(original_text.unique().tolist()),
        "deauth_labels": sorted(selected_deauth),
        "feature_columns": list(features.columns),
        "dropped_identifier_columns": list(dropped),
        "label_column": label_column,
        "random_seed": RANDOM_SEED,
        "original_test_labels": original_test.tolist(),
        "group_column": group_column,
        "split_method": split_method,
        "input_csv_path": str(Path(input_csv_path).resolve()) if input_csv_path else None,
        "data_manifest": data_manifest,
        "window_feature_columns": list(x_train.columns),
    }
    joblib.dump(package, package_path)
    metrics = evaluate_model(y_test, predictions, report_dir=report_dir,
                             original_labels=original_test)
    output_dir = Path(report_dir) if report_dir is not None else Path(__file__).resolve().parents[1] / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    # Feature-only held-out examples can be replayed in the dashboard. Truth labels
    # remain beside predictions in test_predictions.csv for transparent comparison.
    x_test.to_csv(output_dir / "test_features.csv", index=False)
    # Keep original labels and source provenance alongside held-out predictions.
    predictions_frame = pd.DataFrame({
        "original_label": original_test.to_numpy(),
        "binary_label": y_test.to_numpy(),
        "prediction": predictions,
        "predicted_source_label": attack_type_predictions,
    }, index=original_test.index)
    for column in metadata_columns:
        predictions_frame[column] = frame.loc[original_test.index, column]
    predictions_frame.reset_index(drop=True).to_csv(output_dir / "test_predictions.csv", index=False)
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    metrics["split_method"] = split_method
    metrics["attack_type_classification"] = {
        "accuracy": float(accuracy_score(original_test, attack_type_predictions)),
        "labels": sorted(original_text.unique().tolist()),
        "confusion_matrix": confusion_matrix(
            original_test, attack_type_predictions, labels=sorted(original_text.unique().tolist())
        ).tolist(),
    }
    metrics["deauthentication_detection"] = {
        "available": bool(selected_deauth),
        "selected_source_labels": sorted(selected_deauth),
        "support": int(deauth_true.sum()),
    }
    if selected_deauth and int(deauth_true.sum()) > 0:
        metrics["deauthentication_detection"].update({
            "precision": float(precision_score(deauth_true, deauth_pred, zero_division=0)),
            "recall": float(recall_score(deauth_true, deauth_pred, zero_division=0)),
            "f1_score": float(f1_score(deauth_true, deauth_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(deauth_true, deauth_pred, labels=[0, 1]).tolist(),
        })
    elif selected_deauth:
        metrics["deauthentication_detection"]["reason"] = "No selected deauthentication examples occurred in the held-out partition."
    else:
        metrics["deauthentication_detection"]["reason"] = "No original label identified a deauthentication class; choose explicit deauth_labels after inspecting dataset labels."
    metrics["model_path"] = str(package_path)
    metrics["train_rows"] = len(x_train)
    metrics["test_rows"] = len(x_test)
    metrics["purged_rows"] = purged_rows
    metrics["train_binary_class_counts"] = {
        "normal": int((y_train == 0).sum()), "malicious": int((y_train == 1).sum())
    }
    metrics["test_binary_class_counts"] = {
        "normal": int((y_test == 0).sum()), "malicious": int((y_test == 1).sum())
    }
    metrics["train_source_label_counts"] = original_train.value_counts().sort_index().to_dict()
    metrics["test_source_label_counts"] = original_test.value_counts().sort_index().to_dict()
    metrics["dropped_identifier_columns"] = list(dropped)
    metrics["group_column"] = group_column
    metrics["input_csv_path"] = package["input_csv_path"]
    metrics["window_feature_columns"] = list(x_train.columns)
    metrics["test_time_range"] = ([float(times.iloc[test_idx].min()), float(times.iloc[test_idx].max())]
                                   if times is not None else None)
    metrics_path = Path(report_dir) / "metrics.json" if report_dir is not None else Path(__file__).resolve().parents[1] / "reports" / "metrics.json"
    with metrics_path.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    (output_dir / "training_data_manifest.json").write_text(json.dumps({
        "input_csv_path": package["input_csv_path"],
        "source_manifest": data_manifest,
        "input_rows": len(frame),
        "window_label_column": label_column,
        "window_label_counts": original_text.value_counts().sort_index().to_dict(),
        "train_rows": len(train_idx),
        "test_rows": len(test_idx),
        "purged_rows": purged_rows,
        "train_source_label_counts": original_train.value_counts().sort_index().to_dict(),
        "test_source_label_counts": original_test.value_counts().sort_index().to_dict(),
        "group_column": group_column,
        "distinct_groups": int(groups.nunique()) if groups is not None else None,
        "split_method": split_method,
        "time_column": time_column,
        "test_size_requested": test_size,
        "temporal_gap_seconds": temporal_gap_seconds,
        "feature_columns": list(x_train.columns),
        "excluded_columns": list(dropped),
    }, indent=2), encoding="utf-8")
    return metrics


def train_from_csv(path: str | Path, label_column: str = DEFAULT_LABEL_COLUMN,
                   model_path: str | Path = MODEL_PATH,
                   report_dir: str | Path | None = None, group_column: str | None = None,
                   deauth_labels: list[str] | None = None,
                   time_column: str | None = None,
                   temporal_gap_seconds: float = 1.0) -> dict:
    """Convenience wrapper to load a CSV and train on its contents."""
    csv_path = Path(path)
    manifest_path = csv_path.with_suffix(csv_path.suffix + ".manifest.json")
    source_manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    return train_model(load_csv(path), label_column=label_column,
                       model_path=model_path, report_dir=report_dir,
                       group_column=group_column, deauth_labels=deauth_labels,
                       time_column=time_column,
                       temporal_gap_seconds=temporal_gap_seconds,
                       data_manifest=source_manifest, input_csv_path=csv_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train/evaluate the offline WIDS Decision Tree")
    parser.add_argument("csv_path", help="Path to an authorized labeled CSV dataset")
    parser.add_argument("--label-column", default=DEFAULT_LABEL_COLUMN,
                        help="Actual dataset label column name (default: label)")
    parser.add_argument("--group-column", help="Optional capture/session column; keeps each group entirely in train or test")
    parser.add_argument("--time-column", help="Optional ordered time field for a chronological holdout when independent captures are unavailable")
    parser.add_argument("--temporal-gap-seconds", type=float, default=1.0,
                        help="Rows in this many seconds around the chronological boundary are purged")
    parser.add_argument("--deauth-label", action="append", dest="deauth_labels",
                        help="Exact source label for deauthentication; repeat to select multiple labels")
    parser.add_argument("--model-path", default=str(MODEL_PATH), help="Output model package path")
    parser.add_argument("--report-dir", default=None, help="Output directory for this experiment's reports")
    args = parser.parse_args()
    results = train_from_csv(args.csv_path, label_column=args.label_column,
                             model_path=args.model_path, report_dir=args.report_dir,
                             group_column=args.group_column, deauth_labels=args.deauth_labels,
                             time_column=args.time_column,
                             temporal_gap_seconds=args.temporal_gap_seconds)
    print("Training complete. Metrics are saved in reports/metrics.json")
    print(f"Accuracy: {results['accuracy']:.4f}")
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall: {results['recall']:.4f}")
    print(f"F1-score: {results['f1_score']:.4f}")
    print(f"Deauthentication results: {results['deauthentication_detection']}")
