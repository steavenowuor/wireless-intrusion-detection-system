# Ten-minute WIDS prototype demonstration

## Before the demonstration

Open PowerShell in the project folder. Confirm `models/awid3_deauth_baseline_20261031/decision_tree.joblib` exists and the prepared dataset is present. Start the dashboard:

```powershell
# Open PowerShell in the project directory before running these commands.
& .\.venv\Scripts\Activate.ps1
python -m streamlit run app.py
```

## Timed sequence

1. **0:00–0:45 — Problem and scope.** Explain that the project explores identifying windows containing AWID3 Deauth-labelled rows. State clearly that this is offline CSV analysis, not live Wi-Fi monitoring.
2. **0:45–1:45 — Dataset evidence.** Show the dashboard's 604 windows, with 424 Normal and 180 Deauth-containing. Explain that all Deauth windows are mixed source-label windows and the window is positive if at least one source row is Deauth-labelled.
3. **1:45–2:30 — Provenance.** Open the prepared CSV manifest. Explain that 33 chunks form one strongly corroborated frame-ordered sequence; the original pcap name is not established and the chunks are not independent sessions.
4. **2:30–3:30 — Architecture.** Explain: selected AWID3 CSV rows → one-second windows → numeric summary features → split and train Decision Tree → offline CSV prediction and evaluation artifacts.
5. **3:30–4:30 — Leakage control.** Show `feature_columns.json`. Time/frame numbers, file/capture identifiers, source label strings/counts, mixed indicator and direct Deauth count/rate/fraction are excluded. The pipeline fits preprocessing using training rows only.
6. **4:30–5:45 — Evaluation.** Show 483 training / 121 test windows and the class counts. Report accuracy 0.9917, precision 1.0000, recall 0.9722, F1 0.9859, and confusion matrix `[[85, 0], [1, 35]]`. Compare majority baseline accuracy 0.7025.
7. **5:45–7:15 — Dashboard.** Open Model evaluation and show metrics, class counts, confusion matrix and the within-capture caveat. Then use Classify prepared windows with a CSV from `data/`; point out predicted class and confidence/probability.
8. **7:15–8:15 — Interpret carefully.** Explain the one false negative in the test split. State that every positive window contains Normal and Deauth source rows; source labels do not define a verified flood episode.
9. **8:15–9:15 — Tests and reproducibility.** Run `python -m pytest -q` and `python -m compileall -q src app.py tests`. Synthetic test fixtures validate code behavior only, not WIDS performance.
10. **9:15–10:00 — Limitations and next step.** A random split from one capture can place correlated nearby windows in train and test. This result is exploratory and is not independent-capture generalization. Future work requires independently identified, correctly labelled captures and reviewed flood ground truth.

## Exact evaluation reproduction

```powershell
python -m src.run_awid3_baseline `
  --data .\data\awid3_deauth_capture_sequence_windows_v2.csv `
  --output-dir .\models\awid3_deauth_baseline_rerun
```

The target output directory must be new or empty. Do not replace the saved submission artifacts unless you intend to regenerate and re-review the results.

## Safe claims for the presentation

- “The prototype classifies offline one-second AWID3 windows as Normal or Deauth-containing.”
- “The held-out split is a stratified random split within one capture sequence; it is exploratory.”
- “The output label means at least one source packet is Deauth-labelled. It is not a confirmed flood label.”
- “The application does not capture live wireless traffic, transmit, disrupt, or block.”
