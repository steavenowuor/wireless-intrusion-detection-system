# AWID3 preparation and window-feature stage report

Date: 2026-10-26

## Implemented

- Added bounded, explicit-path CSV reading and output of fixed UTC-epoch time-window rows in `src/data_preparation.py`.
- Added handling for invalid/missing timestamps, numeric/hex/boolean Wi-Fi fields, nondecreasing-time validation, chunk-boundary windows, a raw-row cap, a pending-window safety limit, and a JSON provenance/count manifest.
- Added window features in `src/feature_extraction.py`: packet and management-frame counts, type-0/subtype-12 Deauth frame count/rate/fraction, retry statistics, frame length/signal summaries, reason-code count, and distinct-transmitter count. The source `Label` evidence is retained in source-label metadata; the aggregate target is `window_label`.
- Added `evaluate_window_predictions` for binary classification and Deauth-label evaluation. When only binary predictions are supplied, it reports Deauth-labelled-window recall and does not invent Deauth precision. Source-label predictions enable a separate Deauth one-vs-rest confusion matrix and precision/recall/F1.
- Added a chronological training split with a one-second purge for a single known capture, while retaining capture-group splitting when multiple independent groups are present. The split method is recorded in results. Preprocessing remains inside the train-fitted scikit-learn pipeline.
- Added an AWID3 preparation form to the dashboard. It reads only selected files after form submission and can inspect prepared CSVs using the existing training interface. Dashboard image/dataframe APIs were updated for current Streamlit.
- Updated dataset and project documentation with the observed AWID3 schema/labels, the subset workflow, chunk caveats, and Windows commands.

## Capture relationship and limitation

The local AWID3 README describes category selection CSVs being split into 50,000-row chunks. The local `split.sh` directly shows a selection file such as `Deauth2Selection.csv` being split into 50,000-line parts. Thus chunks from one selection series must share one source group; each numbered chunk is not an independent session. The local documentation does not explain the filename transformation from `split_...` outputs to the supplied `Deauth_0.csv` names, and the inspected schema has no `capture_id` or `session_id` field. The exact original pcap/run identity cannot be reconstructed from the tabular header alone. Use an ID established by dataset provenance; the category selection name can be used as a conservative series ID where that mapping is confirmed, but it does not prove multiple independent attack captures.

When only one source group exists, the trainer can make a chronological within-capture holdout and purge a one-second boundary. That is weaker than testing on an independent capture. The source dataset labels rows, not flood episodes. A Deauth-labelled window means at least one row in that window had the `Deauth` label; it does not establish a validated flood threshold. No flood-detection performance is claimed.

The inspected `Deauth_21.csv` contains both source labels at the row level, but the attack rows may occur in a late contiguous interval. A chronological split can therefore have no Deauth examples in its training section (or no class balance on one side) and will reject that split rather than silently use a random row split. Review the prepared window label counts and time ordering before attempting training; more independent Deauth capture periods may be needed.

The 50,000-row `Deauth_21.csv` sample was scanned in 5,000-row chunks using only `Label`, `frame.time_epoch`, `wlan.fc.type`, and `wlan.fc.subtype`. All timestamps parsed as nonnegative numeric values. Of the 885 `Deauth`-labelled rows, 881 have type `0`, subtype `12`, and 4 have type `0`, subtype `10`. Type-0/subtype-12 is the dominant Deauth frame encoding in this sample; the source label remains ground truth.

## Final bounded audit (2026-10-26)

The current verified output and evaluation decision supersede the earlier “next command” section below. See `awid3_bounded_window_audit.md` for independent checks and full counts. Chunks 21–32 yielded 576,472 source rows and 187 one-second windows, with 537,530 Normal and 38,942 Deauth source rows. The window targets are 7 Normal followed by 180 Deauth. An independent four-column raw scan matched packet, management, Deauth-subtype, and source-label aggregation exactly, with monotonic timestamps and no invalid times.

The chronological split was attempted and rejected because the test partition lacks the Normal class. No AWID3 model was fitted and no AWID3 metrics exist. Use `window_label` rather than the source CSV column name `Label` when training on the prepared output. The current corrected manifest accumulates source label counts across all reader chunks; the previous implementation overwrote these counts with the final processed chunk, and a synthetic regression test now guards this behavior.

## Files changed

- `app.py`
- `requirements.txt`
- `README.md`
- `DEMO_GUIDE.md`
- `SUBMISSION_CHECKLIST.md`
- `data/README.md`
- `src/data_preparation.py` (new)
- `src/feature_extraction.py`
- `src/evaluate_model.py`
- `src/train_model.py`
- `tests/test_app.py` (new)
- `tests/test_data_preparation.py` (new)
- `tests/test_feature_extraction.py`
- `tests/test_training.py`
- `tests/test_window_evaluation.py` (new)

## Verification

- `python -m pytest -q`: **22 passed**. All data preparation, feature, evaluation, and training fixtures use tiny synthetic data. The Streamlit app shell passed a headless `AppTest` smoke test.
- `python -m py_compile app.py src/data_preparation.py src/feature_extraction.py src/evaluate_model.py src/train_model.py`: passed.
- No full AWID3 processing or model training was run. The original dataset was not changed.

## Current Windows commands

The exact bounded preparation and dashboard commands are in `DEMO_GUIDE.md` and
`data/README.md`. For the current prepared file, a model attempt is expected to
stop because the chronological test partition lacks Normal windows. No AWID3
model or metrics are available until a suitable class-covered evaluation set
is established.
