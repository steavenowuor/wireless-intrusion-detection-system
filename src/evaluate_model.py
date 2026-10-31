"""Metrics and confusion-matrix output for genuine held-out predictions."""
from pathlib import Path
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, ConfusionMatrixDisplay,
                             classification_report)
from .config import REPORT_DIR


def evaluate_window_predictions(true_labels, predicted_binary,
                                predicted_source_labels=None,
                                deauth_labels=None) -> dict:
    """Return binary and Deauth-label metrics for prepared time windows.

    Without source-label predictions, Deauth results are reported only as
    binary malicious recall on Deauth-labelled windows; precision is not
    claimed because a binary classifier cannot distinguish Deauth from other
    attack categories. With source-label predictions, a separate Deauth
    one-vs-rest confusion matrix and precision/recall/F1 are calculated.
    """
    import pandas as pd
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                 f1_score, confusion_matrix)
    from .data_loader import normalize_binary_labels

    truth_text = pd.Series(true_labels).astype("string").str.strip()
    pred_binary = pd.Series(predicted_binary).reset_index(drop=True)
    if len(truth_text) != len(pred_binary):
        raise ValueError("true_labels and predicted_binary must have equal lengths")
    truth_binary = normalize_binary_labels(truth_text.reset_index(drop=True))
    pred_binary = normalize_binary_labels(pred_binary)
    binary = {
        "accuracy": float(accuracy_score(truth_binary, pred_binary)),
        "precision": float(precision_score(truth_binary, pred_binary, zero_division=0)),
        "recall": float(recall_score(truth_binary, pred_binary, zero_division=0)),
        "f1_score": float(f1_score(truth_binary, pred_binary, zero_division=0)),
        "confusion_matrix": confusion_matrix(truth_binary, pred_binary, labels=[0, 1]).tolist(),
    }
    if deauth_labels is None:
        selected = {str(label).lower() for label in truth_text.dropna().unique()
                    if "deauth" in str(label).lower().replace("_", "").replace("-", "")}
    else:
        selected = {str(label).strip().lower() for label in deauth_labels}
    true_deauth = truth_text.str.lower().isin(selected).astype("int64")
    support = int(true_deauth.sum())
    deauth = {"labels": sorted(selected), "support": support}
    if predicted_source_labels is None:
        caught = int(((true_deauth == 1) & (pred_binary == 1)).sum())
        deauth.update({
            "metric_scope": "binary malicious detection on Deauth-labelled windows",
            "detected_as_malicious": caught,
            "recall": float(caught / support) if support else 0.0,
            "precision_available": False,
            "note": "A binary classifier cannot distinguish Deauth from other malicious labels.",
        })
    else:
        pred_text = pd.Series(predicted_source_labels).astype("string").str.strip().str.lower()
        if len(pred_text) != len(truth_text):
            raise ValueError("predicted_source_labels must match true_labels length")
        pred_deauth = pred_text.isin(selected).astype("int64")
        deauth.update({
            "metric_scope": "Deauth source-label classification",
            "predicted_deauth": int(pred_deauth.sum()),
            "precision_available": True,
            "precision": float(precision_score(true_deauth, pred_deauth, zero_division=0)),
            "recall": float(recall_score(true_deauth, pred_deauth, zero_division=0)),
            "f1_score": float(f1_score(true_deauth, pred_deauth, zero_division=0)),
            "confusion_matrix": confusion_matrix(true_deauth, pred_deauth, labels=[0, 1]).tolist(),
        })
    return {"binary_classification": binary, "deauthentication_detection": deauth}


def evaluate_model(y_true, y_pred, report_dir: str | Path = REPORT_DIR,
                   original_labels=None, predicted_source_labels=None,
                   deauth_labels=None) -> dict:
    """Calculate binary metrics and save JSON, CSV labels, and PNG matrix."""
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix_labels": ["normal (0)", "malicious (1)"],
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=[0, 1], target_names=["normal", "malicious"],
            output_dict=True, zero_division=0,
        ),
    }
    if original_labels is not None:
        # Subtype recall asks whether known rows of each source attack label were caught.
        subtype_rows = {}
        for subtype in sorted({str(value) for value in original_labels
                              if str(value).strip().lower() not in {"normal", "benign", "0"}}):
            mask = [str(value) == subtype for value in original_labels]
            count = sum(mask)
            detected = sum(bool(pred) for pred, belongs in zip(y_pred, mask) if belongs)
            subtype_rows[subtype] = {
                "support": count,
                "detected_as_malicious": detected,
                "recall": (detected / count) if count else 0.0,
            }
        metrics["attack_subtype_detection"] = subtype_rows
        metrics.update(evaluate_window_predictions(
            original_labels, y_pred, predicted_source_labels=predicted_source_labels,
            deauth_labels=deauth_labels,
        ))
    with (out_dir / "metrics.json").open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2)
    display = ConfusionMatrixDisplay(matrix, display_labels=["Normal", "Malicious"])
    display.plot(cmap="Blues", values_format="d")
    plt.title("Held-out test confusion matrix")
    plt.tight_layout()
    plt.savefig(out_dir / "confusion_matrix.png", dpi=150)
    plt.close()
    if original_labels is not None:
        # CSV keeps attack subtypes beside the binary ground truth for later analysis.
        import pandas as pd
        pd.DataFrame({"original_label": list(original_labels),
                      "binary_label": list(y_true),
                      "prediction": list(y_pred)}).to_csv(
                          out_dir / "test_predictions.csv", index=False)
    return metrics
