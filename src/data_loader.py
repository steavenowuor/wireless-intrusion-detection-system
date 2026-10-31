"""Small, explicit CSV loader and binary-label normalization helpers."""
from pathlib import Path
import pandas as pd

NORMAL_LABELS = {"normal", "benign", "0"}


def load_csv(path: str | Path) -> pd.DataFrame:
    """Read a CSV and report a useful error if it is missing or empty."""
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset CSV was not found: {csv_path}")
    frame = pd.read_csv(csv_path)
    if frame.empty:
        raise ValueError(f"Dataset CSV contains no rows: {csv_path}")
    if frame.columns.empty:
        raise ValueError("Dataset CSV has no columns")
    return frame


def normalize_binary_labels(labels: pd.Series) -> pd.Series:
    """Map normal/benign/0 to 0 and other non-empty attack names to 1."""
    if labels.isna().any():
        raise ValueError("Label column contains missing values")
    def convert(value):
        if isinstance(value, (int, float)) and value in (0, 1):
            return int(value)
        text = str(value).strip().lower()
        if not text:
            raise ValueError("Label column contains an empty value")
        if text in {"0", "1"}:
            return int(text)
        return 0 if text in NORMAL_LABELS else 1
    return labels.map(convert).astype("int64")


def split_features_and_labels(frame: pd.DataFrame, label_column: str):
    """Validate and split the target from feature columns."""
    if label_column not in frame.columns:
        raise ValueError(
            f"Label column '{label_column}' is missing. Available columns: "
            + ", ".join(map(str, frame.columns))
        )
    if len(frame.columns) < 2:
        raise ValueError("Dataset needs at least one feature column and a label column")
    # Keep the original labels separately for attack-specific analysis later.
    original_labels = frame[label_column].copy()
    features = frame.drop(columns=[label_column]).copy()
    if features.columns.duplicated().any():
        raise ValueError("Feature column names must be unique")
    return features, normalize_binary_labels(original_labels), original_labels
