"""Window-evaluation behavior tests use synthetic labels and predictions only."""

import pytest

pytest.importorskip("sklearn")

from src.evaluate_model import evaluate_window_predictions


def test_synthetic_binary_eval_reports_deauth_recall_without_false_precision():
    result = evaluate_window_predictions(
        ["Normal", "Deauth", "KRACK", "Normal"], [0, 1, 1, 1]
    )
    assert result["binary_classification"]["confusion_matrix"] == [[1, 1], [0, 2]]
    deauth = result["deauthentication_detection"]
    assert deauth["support"] == 1
    assert deauth["recall"] == 1.0
    assert deauth["precision_available"] is False


def test_synthetic_source_label_eval_calculates_deauth_one_vs_rest_metrics():
    result = evaluate_window_predictions(
        ["Normal", "Deauth", "KRACK", "Deauth"], [0, 1, 1, 1],
        predicted_source_labels=["Normal", "Deauth", "Deauth", "Normal"],
    )
    deauth = result["deauthentication_detection"]
    assert deauth["support"] == 2
    assert deauth["predicted_deauth"] == 2
    assert deauth["confusion_matrix"] == [[1, 1], [1, 1]]
    assert deauth["precision"] == 0.5
    assert deauth["recall"] == 0.5


def test_synthetic_eval_rejects_mismatched_lengths():
    with pytest.raises(ValueError, match="equal lengths"):
        evaluate_window_predictions(["Normal"], [0, 1])
