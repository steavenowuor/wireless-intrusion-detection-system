# Offline AWID3 Wireless Intrusion Detection Prototype

## Abstract

This project implements an offline CSV-based prototype that classifies one-second AWID3 Deauth-sequence windows as Normal or Deauth-containing. A scikit-learn Decision Tree was trained on curated numeric summaries. Its stratified random holdout results are high, but exploratory only: all windows come from one strongly corroborated capture sequence, so correlated neighboring windows may occur in both partitions. The results do not establish performance on a different capture, live network, or verified deauthentication flood.

## Objective and scope

The objective is to demonstrate a reproducible wireless intrusion detection workflow on an existing labeled dataset. The current application consumes prepared AWID3 CSV windows. It does not capture live packets, use a monitor-mode adapter, inspect ordinary Windows network traffic as raw Wi-Fi frames, inject packets, disrupt networks, or block clients.

## Dataset and preparation

The evaluated file is `data/awid3_deauth_capture_sequence_windows_v2.csv`, generated from `Deauth_0.csv` through `Deauth_32.csv` in numeric order. Preparation parsed 1,626,469 source rows and produced 604 one-second windows: 424 Normal-only and 180 Deauth-containing. Source row labels total 1,587,527 Normal and 38,942 Deauth. All 180 Deauth-labelled windows are mixed: each contains both Normal and Deauth source rows.

The window rule is **Deauth if at least one source row is labelled Deauth, otherwise Normal**. Original source label counts and source filenames remain in the prepared file/manifest. Source `Label=Deauth` and a derived Deauth-containing window are not independent evidence of an attack flood.

The 33 chunks are strongly corroborated as one frame-ordered Deauth sequence by frame-number ordering/continuity and the published Deauth frame interval. The original pcap filename is not explicitly established. There are three missing frame numbers and four timestamp backsteps, with maximum 0.346640 seconds; epoch timestamps were retained. This is one capture group, not 33 independent captures. See `data/README.md`, the preparation report, and the JSON manifest for details.

AWID3 is a publicly described WLAN dataset; the exact downloaded edition and access/licensing terms must be cited according to the course requirements. Official information: [AWID3 dataset page](https://icsdweb.aegean.gr/awid/awid3).

## Architecture and workflow

1. Explicit AWID3 CSV source files are read in bounded pandas chunks.
2. Verified `frame.number` order supports cross-chunk aggregation; source epoch timestamps are preserved and anomalies recorded.
3. Packet observations become fixed, one-second windows with packet, management-frame, retry, frame-length, signal and transmitter summaries.
4. A manifest records source rows, label counts, row limits, file order, timestamp anomalies, window labels and provenance confidence.
5. A curated set of numeric window summaries enters an sklearn preprocessing/classifier pipeline.
6. Held-out metrics, a confusion matrix and predictions are saved; Streamlit displays status, evaluation, and non-disruptive CSV predictions.

## Model and features

Model: scikit-learn `DecisionTreeClassifier`, fixed random seed 42. Model features:

- `packet_count`
- `management_frame_count`
- `retry_frame_count`
- `retry_frame_fraction`
- `frame_len_mean`
- `frame_len_max`
- `signal_dbm_mean`
- `signal_dbm_min`
- `unique_transmitter_count`

The feature list was chosen to exclude capture/file identifiers, timestamps and frame ordering, source labels/count strings, the mixed-window indicator, the target, and direct Deauth count/rate/fraction fields. The last group would encode evidence closely tied to how the target windows were formed. Features are numeric and were complete in the audited prepared file. Imputation/scaling/encoding are not needed for these curated numeric features; the existing pipeline still puts preprocessing inside sklearn's Pipeline so any fit occurs on training rows only.

## Evaluation design

The complete dataset has 604 observations: 424 Normal (70.20%) and 180 Deauth-containing (29.80%). We used a reproducible, stratified 80/20 random holdout because the assignment required an initial exploratory split and the single-sequence windows contain both labels. Seed: 42. No capture grouping was claimed. The split is explicitly within-capture exploration, not independent-capture validation. Since adjacent temporal windows may be correlated, random partitioning can overstate generalization.

Training: 483 windows (339 Normal, 144 Deauth). Test: 121 windows (85 Normal, 36 Deauth). No rows were purged. Train and test proportions were stratified by original source label.

## Results

| Metric | Decision Tree | Majority baseline |
|---|---:|---:|
| Accuracy | 0.9917 | 0.7025 |
| Precision (Deauth positive class) | 1.0000 | 0.0000 |
| Recall (Deauth positive class) | 0.9722 | 0.0000 |
| F1-score (Deauth positive class) | 0.9859 | 0.0000 |

Confusion matrix, actual rows and predicted columns in order Normal, Deauth:

|  | Predicted Normal | Predicted Deauth |
|---|---:|---:|
| Actual Normal | 85 | 0 |
| Actual Deauth | 1 | 35 |

On the held-out 36 Deauth-containing windows, Deauth precision was 1.0000, recall 0.9722, F1 0.9859; one Deauth-containing window was classified Normal. These results are generated by the actual saved evaluation run and are recorded in `models/awid3_deauth_baseline_20261031/metrics.json`. The majority comparator predicts the training majority class (Normal) for every test example.

## Limitations and interpretation

- One strongly corroborated ordered capture sequence only; exact original pcap name unknown.
- A stratified random split permits nearby/correlated windows in both partitions. Metrics may overstate performance on new time periods or captures.
- No independent capture/session generalization has been tested.
- A Deauth-containing target is based on AWID3 row labels, and every positive window is mixed with Normal rows. No separate flood episode labels or threshold were tested; therefore this is not verified flood detection.
- Predictions on the full 604-window input include training windows and must not be reported as held-out results.
- Signal measurements and management summaries reflect this AWID3 export; real deployment and live monitoring are outside scope.

## Reproduction and artifacts

In PowerShell from the project root:

```powershell
& .\.venv\Scripts\Activate.ps1
python -m src.run_awid3_baseline `
  --data .\data\awid3_deauth_capture_sequence_windows_v2.csv `
  --output-dir .\models\awid3_deauth_baseline_rerun
python -m pytest -q
python -m compileall -q src app.py tests
python -m streamlit run app.py
```

The chosen output directory must be new/empty. The dated run directory stores the fitted model, feature list, evaluation metrics, confusion matrix, held-out features/predictions, majority baseline, and experiment/training manifests. Full test and compilation results are reported with the submission files.

## Software verification

The full automated suite completed with **38 passed**. `python -m compileall -q src app.py tests` completed successfully. The Streamlit smoke test verifies the dashboard renders and the provenance controls are available; tests use synthetic fixtures for software behavior and are not model performance results.
