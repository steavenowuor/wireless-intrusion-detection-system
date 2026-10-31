# Offline AWID3 Wireless Intrusion Detection Prototype

This university prototype classifies **prepared AWID3 CSV windows** as Normal or Deauth-containing. It is offline analysis: it does not capture live Wi-Fi frames, monitor a network, transmit packets, block traffic, or prove that a Deauth-labelled window is a flood.

## Setup on Windows (PowerShell)

From the project directory:

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pytest -q
python -m compileall -q src app.py tests
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal and activate again. Keep the full licensed AWID3 dataset outside Git. This project does not download the dataset automatically.

## Dataset and preparation

The evaluated prepared file is `data/awid3_deauth_capture_sequence_windows_v2.csv`; its sidecar manifest records the source files, row counts, frame ordering, timestamp anomalies, and provenance notes. It contains 604 one-second windows: 424 Normal and 180 Deauth-containing. All 180 Deauth windows are mixed windows containing Normal and Deauth source rows. The window target rule is `Deauth` if any source row has `Label=Deauth`, otherwise `Normal`.

The windows originate from one strongly corroborated, frame-ordered AWID3 Deauth sequence. The original pcap filename is not established, and the 33 CSV chunks are not independent capture sessions. See `data/README.md` and `reports/awid3_capture_sequence_preparation_report.md` for reproducible preparation and verified limitations. AWID3 source labels do not define a Deauth flood threshold.

### GitHub data handling

The repository intentionally excludes every CSV under `data/`, including prepared/derived windows, and the held-out feature and prediction CSVs under the model output folder. It does not include the original AWID3 files. After cloning, provide an authorized prepared-window CSV locally in `data/` or upload one in the dashboard. To reproduce training, place the audited prepared file at `data/awid3_deauth_capture_sequence_windows_v2.csv` first. Keep the dataset's access and licensing terms in mind; never add the raw dataset to this repository.

## Train the baseline

The audited baseline has already been run and its new artifacts are saved under `models/awid3_deauth_baseline_20261031/`. To reproduce it, use the same file and output folder only after moving the previous output aside or choosing a new empty folder; the script refuses to overwrite a non-empty result directory.

```powershell
python -m src.run_awid3_baseline `
  --data .\data\awid3_deauth_capture_sequence_windows_v2.csv `
  --output-dir .\models\awid3_deauth_baseline_rerun
```

The script validates the expected dataset labels and counts. It uses nine numeric window summaries and excludes identifiers, filenames, time/frame ordering, original label strings/counts, the mixed indicator, and direct Deauth count/rate/fraction fields. The scikit-learn pipeline fits its preprocessing on training rows only. The seeded 80/20 split is stratified randomly across windows. This is explicitly an **exploratory within-capture holdout**; neighbouring windows from one sequence may be correlated. The result does not show independent-capture generalization.

### Recorded evaluation result

The reproducible run used seed 42: 483 training windows (339 Normal, 144 Deauth) and 121 held-out windows (85 Normal, 36 Deauth). Decision Tree accuracy was **0.9917**, precision **1.0000**, recall **0.9722**, and F1 **0.9859**. Confusion matrix (actual rows, predicted columns; Normal then Deauth): `[[85, 0], [1, 35]]`. The majority-class baseline always predicted Normal: accuracy **0.7025**, Deauth precision/recall/F1 **0**. These figures are exploratory, from one capture sequence only.

The local output directory contains `decision_tree.joblib`, `feature_columns.json`, `metrics.json`, `confusion_matrix.png`, `test_features.csv`, `test_predictions.csv`, `majority_baseline.json`, `experiment_manifest.json`, and `training_data_manifest.json`. The model, feature list, evaluation metrics, confusion matrix, majority baseline, and experiment manifest are preserved for publishing. Git excludes derived CSV tables and `training_data_manifest.json`, which contains machine-specific source paths and detailed source metadata. The held-out results evaluate windows containing Deauth-labelled source rows, not independently confirmed flood episodes.

## Launch the dashboard

```powershell
# Run this from the project directory in PowerShell.
& .\.venv\Scripts\Activate.ps1
python -m streamlit run app.py
```

The dashboard shows dataset counts, held-out metrics and confusion matrix, supports selecting a CSV in `data/` or uploading a prepared window CSV, and provides predictions with probabilities when the classifier supports them. Predictions on the full dataset include training observations and are not evaluation results; use the saved held-out evaluation for reported performance.

## Project modules

- `app.py`: offline preparation form, evaluation view, dataset statistics, and CSV inference.
- `src/data_preparation.py`: bounded AWID3 source streaming and manifest generation.
- `src/feature_extraction.py`: validation and one-second management-traffic summary features.
- `src/run_awid3_baseline.py`: validates and trains the documented curated baseline and majority comparator.
- `src/train_model.py`: reproducible split, training-only preprocessing, Decision Tree, and metrics/artifact generation.
- `src/detector.py`: saved-model inference helpers and review alerts.
- `src/evaluate_model.py`: classification metrics, confusion matrix, and Deauth-specific evaluation.
- `tests/`: synthetic fixtures for software behavior; these are not AWID3 performance evidence.

## Technologies used

Python 3, pandas, NumPy, scikit-learn (Decision Tree and preprocessing pipeline), Streamlit, matplotlib (confusion-matrix image), joblib (model persistence), and pytest (automated tests).

## References and limitations

AWID3 dataset information: [official AWID3 site](https://icsdweb.aegean.gr/awid/awid3). Cite the exact downloaded edition and follow its access/licensing terms. The current experiment has one strongly corroborated Deauth capture sequence, an unestablished original pcap name, and no independent capture/session test set. A random split can put correlated neighbouring windows on both sides. No conclusion about performance on other captures, live Wi-Fi, or a Deauth flood should be drawn from these metrics.
