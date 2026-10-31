"""Detector shell tests use synthetic temporary paths only."""
from src.detector import make_alerts, model_available, predict
import pandas as pd
import pytest


def test_no_model_is_reported_when_artifact_is_absent(tmp_path):
    assert model_available(tmp_path / "synthetic-model.joblib") is False


def test_prediction_is_not_claimed_before_training():
    with pytest.raises(FileNotFoundError, match="Trained model"):
        predict(None, path="missing-synthetic-model.joblib")


def test_alerts_are_non_disruptive_and_match_rows():
    features = pd.DataFrame({"synthetic_feature": [1, 2]})
    alerts = make_alerts(features, [0, 1])
    assert alerts["status"].tolist() == ["Normal", "Suspicious: malicious class"]
    assert "Review" in alerts.iloc[1]["alert"]
    with pytest.raises(ValueError, match="match"):
        make_alerts(features, [1])
