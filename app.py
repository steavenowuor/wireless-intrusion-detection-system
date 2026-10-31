"""Streamlit dashboard for the offline AWID3 WIDS prototype."""
from __future__ import annotations

import json
import re
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.config import DATA_DIR
from src.data_preparation import prepare_awid3_subset

ROOT = Path(__file__).resolve().parent
DATASET = DATA_DIR / "awid3_deauth_capture_sequence_windows_v2.csv"
EXPERIMENT_DIR = ROOT / "models" / "awid3_deauth_baseline_20261031"
MODEL_PATH = EXPERIMENT_DIR / "decision_tree.joblib"
METRICS_PATH = EXPERIMENT_DIR / "metrics.json"
FEATURE_PATH = EXPERIMENT_DIR / "feature_columns.json"

st.set_page_config(page_title="Offline AWID3 WIDS", page_icon="📡", layout="wide")
st.title("Offline Wireless Intrusion Detection")
st.caption("AWID3 CSV prototype · one-second windows · Decision Tree · no live packet capture")
st.warning(
    "This application analyzes prepared offline CSV windows only. It does not monitor live Wi-Fi, "
    "capture packets, transmit or block traffic, or verify that a Deauth-labelled window is a flood."
)

prepare_tab, results_tab, classify_tab, status_tab = st.tabs(
    ["Prepare selected CSVs", "Model evaluation", "Classify prepared windows", "Dataset and model status"]
)

with prepare_tab:
    st.subheader("Prepare selected AWID3 chunks")
    st.write("Preparation reads only files you select and processes them in bounded chunks. The form's capture tag is provenance metadata, not proof of an original capture identity.")
    source_directory = st.text_input(
        "AWID3 category folder", placeholder="Select the local AWID3 category folder",
        key="awid3_source_directory",
    )
    source_path = Path(source_directory) if source_directory.strip() else None
    source_files = []
    if source_path and source_path.is_dir():
        def natural_key(path: Path):
            return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", path.name)]
        source_files = sorted(source_path.glob("*.csv"), key=natural_key)
        st.caption(f"Found {len(source_files):,} CSV file(s); files are read only after submission.")
    elif source_directory.strip():
        st.warning("That directory was not found. Check the local path.")
    if source_files:
        with st.form("awid3_prepare_form"):
            selected_names = st.multiselect("Select CSV files", [p.name for p in source_files])
            capture_id = st.text_input("Capture/session group tag", value="AWID3-Deauth-series-unverified", key="capture_group_tag")
            capture_id_verified = st.checkbox("Verified from original capture/session provenance", value=False, key="capture_id_verified")
            window_seconds = st.number_input("Window duration (seconds)", min_value=0.1, max_value=60.0, value=1.0)
            chunksize = st.number_input("Rows per processing chunk", min_value=1000, max_value=100000, value=50000, step=5000)
            max_rows = st.number_input("Maximum source rows", min_value=1000, max_value=1000000, value=600000, step=50000)
            output_text = st.text_input("New output CSV path", value=str(DATA_DIR / "awid3_prepared_windows_new.csv"))
            submitted = st.form_submit_button("Prepare selected windows", type="primary")
        if submitted:
            if not selected_names or not capture_id.strip():
                st.error("Select at least one CSV and enter a capture/session tag.")
            else:
                try:
                    summary = prepare_awid3_subset(
                        [p for p in source_files if p.name in selected_names], Path(output_text),
                        capture_id.strip(), float(window_seconds), int(chunksize), int(max_rows),
                        capture_id_verified=capture_id_verified,
                    )
                    st.success(f"Prepared {summary['rows_read']:,} rows from {len(summary['files_completed'])} completed file(s).")
                    st.json(summary)
                    if summary["row_cap_reached"]:
                        st.warning(f"Row limit reached. Partial files: {summary['files_partially_read']}; not started: {summary['files_not_started']}.")
                except Exception as exc:
                    st.error(f"Preparation failed: {exc}")
    else:
        st.info("Enter a local category-folder path to list CSV chunks. No files are read until you submit the form.")

@st.cache_data(max_entries=4)
def load_prepared_csv(path_text: str, modified: float) -> pd.DataFrame:
    del modified  # Included in the cache key so edits refresh the preview.
    return pd.read_csv(path_text)

with results_tab:
    st.subheader("Exploratory held-out evaluation")
    if not METRICS_PATH.is_file():
        st.info("No saved AWID3 model evaluation is available yet.")
    else:
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        st.info(metrics.get("evaluation_scope", "Evaluation scope is not recorded."), title="Within-capture limitation")
        st.caption("One strongly corroborated Deauth sequence; the original pcap identity is unknown. This random window split does not establish independent-capture generalization.")
        a, b, c, d = st.columns(4)
        a.metric("Accuracy", f"{metrics['accuracy']:.3f}")
        b.metric("Precision", f"{metrics['precision']:.3f}")
        c.metric("Recall", f"{metrics['recall']:.3f}")
        d.metric("F1-score", f"{metrics['f1_score']:.3f}")
        st.write(f"Split: **{metrics['split_method']}** · train **{metrics['train_rows']}** · test **{metrics['test_rows']}** · seed **42**")
        st.write("Train class counts:", metrics["train_binary_class_counts"], "· Test class counts:", metrics["test_binary_class_counts"])
        st.write("Confusion matrix (rows = actual; columns = predicted; Normal, Deauth):")
        st.dataframe(pd.DataFrame(metrics["confusion_matrix"], index=["Actual Normal", "Actual Deauth"], columns=["Predicted Normal", "Predicted Deauth"]), width="stretch")
        baseline = metrics["majority_class_baseline"]
        st.write(f"Majority-class baseline accuracy: **{baseline['accuracy']:.3f}** (always predict {baseline['predicted_class']}).")
        st.write("Deauth one-vs-rest metrics:", metrics["deauthentication_detection"])
        st.caption("The target is a window containing at least one Deauth-labelled source row. It is not a ground-truth flood episode.")

with classify_tab:
    st.subheader("Classify prepared window rows")
    if not MODEL_PATH.is_file():
        st.warning("The saved AWID3 model is unavailable. Run the documented training command first.")
    source_choice = st.radio("CSV source", ["Use prepared dataset in data/", "Upload prepared window CSV"], horizontal=True)
    input_frame = None
    if source_choice == "Use prepared dataset in data/":
        candidates = sorted(DATA_DIR.glob("*.csv")) if DATA_DIR.is_dir() else []
        default_idx = next((i for i, p in enumerate(candidates) if p == DATASET), 0)
        if candidates:
            selected_csv = st.selectbox("Prepared CSV", candidates, index=default_idx, format_func=lambda p: p.name)
            try:
                input_frame = load_prepared_csv(str(selected_csv), selected_csv.stat().st_mtime)
            except Exception as exc:
                st.error(f"Could not load CSV: {exc}")
        else:
            st.info("No prepared CSV files are available in data/.")
    else:
        uploaded = st.file_uploader("Upload a prepared window CSV", type=["csv"])
        if uploaded is not None:
            try:
                input_frame = pd.read_csv(uploaded)
            except Exception as exc:
                st.error(f"Could not read uploaded CSV: {exc}")
    if input_frame is not None:
        st.write(f"Loaded {len(input_frame):,} rows × {len(input_frame.columns)} columns.")
        counts = input_frame["window_label"].value_counts(dropna=False).to_dict() if "window_label" in input_frame else None
        if counts is not None:
            st.write("Observed window-label distribution:", counts)
        st.dataframe(input_frame.head(8), width="stretch")
        if MODEL_PATH.is_file() and st.button("Classify windows", type="primary"):
            try:
                package = joblib.load(MODEL_PATH)
                features = package["feature_columns"]
                absent = [name for name in features if name not in input_frame.columns]
                if absent:
                    raise ValueError(f"CSV is missing model features: {absent}")
                x = input_frame[features]
                pipeline = package["pipeline"]
                predicted = pipeline.predict(x)
                output = input_frame.copy()
                output["predicted_class"] = pd.Series(predicted).map({0: "Normal", 1: "Deauth-containing"}).to_numpy()
                if hasattr(pipeline, "predict_proba"):
                    probabilities = pipeline.predict_proba(x)
                    classes = list(pipeline.named_steps["classifier"].classes_)
                    if 1 in classes:
                        output["deauth_probability"] = probabilities[:, classes.index(1)]
                    output["prediction_confidence"] = probabilities.max(axis=1)
                st.warning("Predictions on this CSV are inference output. If it is the training dataset, this is not held-out evaluation.")
                st.dataframe(output.head(100), width="stretch")
                st.download_button("Download predictions", output.to_csv(index=False), file_name="awid3_window_predictions.csv", mime="text/csv")
            except Exception as exc:
                st.error(f"Classification failed: {exc}")

with status_tab:
    st.subheader("Dataset and saved artifacts")
    if DATASET.is_file():
        try:
            full = load_prepared_csv(str(DATASET), DATASET.stat().st_mtime)
            st.write(f"Verified prepared dataset: **{DATASET.name}** · {len(full):,} windows · {len(full.columns)} columns")
            if "window_label" in full:
                distribution = full["window_label"].value_counts().rename_axis("window label").reset_index(name="windows")
                st.dataframe(distribution, width="stretch")
            st.caption("All windows are from one strongly corroborated ordered Deauth sequence. It is not independent-capture validation.")
        except Exception as exc:
            st.error(f"Could not read prepared dataset: {exc}")
    else:
        st.warning(f"Prepared AWID3 file not found: {DATASET}")
    st.write("Saved Decision Tree:", "Available" if MODEL_PATH.is_file() else "Not available")
    st.write("Saved evaluation:", "Available" if METRICS_PATH.is_file() else "Not available")
    st.caption("Offline AWID3 CSV prototype only. No live capture, packet injection, disruption, blocking, or verified flood detection.")
