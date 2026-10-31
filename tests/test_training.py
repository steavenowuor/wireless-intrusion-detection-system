"""Training/evaluation integration test using a small synthetic dataset only."""
import json
import pandas as pd
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("matplotlib")

from src.train_model import train_model
from src.detector import predict, predict_attack_type


def test_synthetic_training_saves_pipeline_metrics_and_matrix(tmp_path):
    # This fixture checks the code path only; it is not AWID3 or performance evidence.
    rows = []
    for i in range(30):
        malicious = i % 2
        rows.append({"frame_length": 400 if malicious else 100,
                     "frame_kind": "management" if malicious else "data",
                     "device_id": f"synthetic-{i}",
                     "label": "deauthentication" if malicious else "normal"})
    model_path = tmp_path / "models" / "model.joblib"
    reports = tmp_path / "reports"
    result = train_model(pd.DataFrame(rows), model_path=model_path, report_dir=reports)
    assert model_path.is_file()
    assert (reports / "confusion_matrix.png").is_file()
    assert (reports / "test_features.csv").is_file()
    saved = json.loads((reports / "metrics.json").read_text(encoding="utf-8"))
    assert set(("accuracy", "precision", "recall", "f1_score", "confusion_matrix")) <= saved.keys()
    assert saved["deauthentication_detection"]["available"] is True
    assert saved["deauthentication_detection"]["support"] > 0
    assert set(("precision", "recall", "f1_score", "confusion_matrix")) <= saved["deauthentication_detection"].keys()
    assert result["train_rows"] + result["test_rows"] == 30
    assert result["dropped_identifier_columns"] == ["device_id"]
    assert result["deauthentication_detection"]["available"] is True
    assert result["deauthentication_detection"]["support"] > 0
    synthetic_observation = pd.DataFrame({"frame_length": [400], "frame_kind": ["management"]})
    assert len(predict(synthetic_observation, model_path)) == 1
    assert predict_attack_type(synthetic_observation, model_path).tolist() == ["deauthentication"]


def test_grouped_synthetic_split_records_grouping_method(tmp_path):
    rows = []
    for i in range(30):
        malicious = i % 2
        rows.append({"frame_length": 400 if malicious else 100,
                     "capture_id": f"synthetic-session-{i // 2}",
                     "label": "deauthentication" if malicious else "normal"})
    result = train_model(pd.DataFrame(rows), group_column="capture_id",
                         model_path=tmp_path / "model.joblib",
                         report_dir=tmp_path / "reports")
    assert result["split_method"] == "group shuffle by capture_id"
    assert result["deauthentication_detection"]["support"] > 0


def test_single_capture_uses_synthetic_chronological_holdout(tmp_path):
    rows = []
    for i in range(100):
        malicious = i % 2
        rows.append({"packet_count": 10 + malicious * 5,
                     "capture_id": "synthetic-one-capture",
                     "window_start_epoch": float(i),
                     "source_files": f"synthetic_part_{i // 10}.csv",
                     "source_labels": "Deauth" if malicious else "Normal",
                     "source_label_counts": '{"Deauth": 1}' if malicious else '{"Normal": 1}',
                     "Label": "Deauth" if malicious else "Normal"})
    result = train_model(pd.DataFrame(rows), label_column="Label",
                         group_column="capture_id", time_column="window_start_epoch",
                         model_path=tmp_path / "model.joblib",
                         report_dir=tmp_path / "reports")
    assert result["split_method"].startswith("chronological holdout")
    assert "within-capture" in result["split_method"]
    assert result["train_rows"] + result["test_rows"] < 100  # Purged boundary windows.
    assert "window_start_epoch" in result["dropped_identifier_columns"]
    assert "capture_id" in pd.read_csv(tmp_path / "reports" / "test_predictions.csv").columns
    saved_data = json.loads((tmp_path / "reports" / "training_data_manifest.json").read_text())
    assert saved_data["split_method"].startswith("chronological holdout")
    assert saved_data["purged_rows"] == result["purged_rows"]


def test_chronological_split_rejects_synthetic_attack_only_at_end(tmp_path):
    rows = [{"packet_count": i, "capture_id": "synthetic-one-capture",
             "window_start_epoch": float(i),
             "Label": "Normal" if i < 90 else "Deauth"}
            for i in range(100)]
    with pytest.raises(ValueError, match="both binary classes"):
        train_model(pd.DataFrame(rows), label_column="Label",
                    group_column="capture_id", time_column="window_start_epoch",
                    model_path=tmp_path / "model.joblib",
                    report_dir=tmp_path / "reports")
