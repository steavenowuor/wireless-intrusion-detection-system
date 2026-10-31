"""Inference interface shell; no trained classifier exists in Stage 1."""
from pathlib import Path
import joblib
import pandas as pd
from .config import MODEL_PATH
from .feature_extraction import validate_feature_frame


def model_available(path: str | Path = MODEL_PATH) -> bool:
    """Return whether a saved model artifact exists."""
    return Path(path).is_file()


def predict(features: pd.DataFrame, path: str | Path = MODEL_PATH):
    """Predict binary labels using a saved fitted pipeline."""
    model_path = Path(path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Trained model was not found: {model_path}")
    frame = validate_feature_frame(features)
    package = joblib.load(model_path)
    expected = package["feature_columns"]
    absent = [column for column in expected if column not in frame.columns]
    extra = [column for column in frame.columns if column not in expected]
    if absent or extra:
        raise ValueError(f"Feature columns do not match model. Missing: {absent}; unexpected: {extra}")
    return package["pipeline"].predict(frame[expected])


def predict_attack_type(features: pd.DataFrame, path: str | Path = MODEL_PATH):
    """Predict the original dataset class using the separately trained subtype model."""
    model_path = Path(path)
    if not model_path.is_file():
        raise FileNotFoundError(f"Trained model was not found: {model_path}")
    frame = validate_feature_frame(features)
    package = joblib.load(model_path)
    expected = package["feature_columns"]
    absent = [column for column in expected if column not in frame.columns]
    extra = [column for column in frame.columns if column not in expected]
    if absent or extra:
        raise ValueError(f"Feature columns do not match model. Missing: {absent}; unexpected: {extra}")
    return package["attack_type_pipeline"].predict(frame[expected])


def make_alerts(features: pd.DataFrame, predictions, attack_type_predictions=None,
                deauth_labels=()) -> pd.DataFrame:
    """Create readable, non-disruptive alerts from binary model predictions."""
    if len(features) != len(predictions):
        raise ValueError("Number of predictions must match number of feature rows")
    result = pd.DataFrame({"prediction": list(predictions)}, index=features.index)
    result["status"] = result["prediction"].map({0: "Normal", 1: "Suspicious: malicious class"})
    result["alert"] = result["prediction"].map({
        0: "No malicious classification from the model.",
        1: "Model classified this observation as malicious. Review the source data.",
    })
    if attack_type_predictions is not None:
        if len(features) != len(attack_type_predictions):
            raise ValueError("Number of attack-type predictions must match number of feature rows")
        result["predicted_source_label"] = list(attack_type_predictions)
        result["possible_deauthentication"] = result["predicted_source_label"].astype(str).str.lower().isin(deauth_labels)
        result.loc[result["possible_deauthentication"], "alert"] = (
            "Attack-type model predicted a source label selected as deauthentication. Review the source data."
        )
    return result
