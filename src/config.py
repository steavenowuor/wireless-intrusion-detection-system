"""Shared paths and reproducibility settings."""
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data"
MODEL_DIR = ROOT_DIR / "models"
REPORT_DIR = ROOT_DIR / "reports"
RANDOM_SEED = 42
DEFAULT_LABEL_COLUMN = "label"
MODEL_PATH = MODEL_DIR / "decision_tree.joblib"
