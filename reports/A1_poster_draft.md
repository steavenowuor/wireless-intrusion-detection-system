# A1 poster draft — offline WIDS with AWID3

**Status:** submission draft. Replace bracketed screenshot placeholders only
with genuine dashboard captures. No AWID3 model results are available yet.

## Title

**Offline Wireless Intrusion Detection Using Labelled AWID3 Time Windows**

## Problem statement

Wireless intrusion analysis benefits from repeatable evaluation on labelled
traffic. This student prototype explores offline feature extraction and
classification without assuming that a Windows Wi-Fi adapter can expose raw
802.11 frames.

## Objectives

1. Prepare a bounded portion of a large AWID3 CSV dataset without loading the
   complete source into memory.
2. Aggregate timestamped 802.11 observations into fixed time windows and
   preserve original labels and provenance.
3. Provide a reproducible Normal-versus-Malicious Decision Tree pipeline with
   capture-aware or chronological evaluation safeguards.
4. Report only results supported by a suitable held-out split.

## Architecture

```text
Authorized AWID3 CSV chunks
          ↓ explicit paths + chunked reader
Timestamp/802.11 field validation
          ↓ fixed 1-second UTC-epoch bins
Window statistics + source labels + manifest
          ↓ leakage-aware split (not valid for current subset)
Train-fitted preprocessing → Decision Tree
          ↓ held-out evaluation when both classes exist
Metrics, confusion matrix, predictions, provenance
          ↓
Streamlit offline inspection interface
```

## Dataset and current subset

- Dataset: local AWID3 CSV edition; inspect `reports/awid3_inspection_report.md`
  for the source schema and citation details.
- Source columns observed: 253 extracted features plus `Label` (254 total).
- Selected files: `Deauth_21.csv` through `Deauth_32.csv`, a contiguous series
  of chunks, not 12 independent captures.
- Processed: 576,472 rows; 187 one-second windows; timestamps were monotonic.
- Source labels: Normal 537,530; Deauth 38,942.
- Derived windows: Normal 7; Deauth 180. A Deauth-labelled window may also
  contain Normal rows.
- Window features include packet/management counts, WLAN type-0/subtype-12
  frame count and rate, retries, frame length, signal, reason codes, and
  transmitter cardinality.

## Method and model

The CSV reader uses selected columns and 50,000-row chunks. It carries a
pending time bin across reader chunk boundaries, verifies nondecreasing epoch
timestamps, and writes a JSON manifest. The source capture ID is absent from
the CSV schema, so the series ID is provisional. A Decision Tree with a fixed
seed and training-only imputation/encoding is implemented. Target, provenance,
address, identifier, and raw chronology fields are excluded from predictors.

## Results (verified)

**No model metrics are available.** A chronological holdout was attempted and
the code stopped before fitting because all seven Normal windows occur before
the Deauth interval; the held-out period did not contain both classes. No
accuracy, precision, recall, F1, or confusion matrix should be reported as
AWID3 performance from this subset.

The independent audit confirmed 576,472 rows, 187 bins, monotonic timestamps,
and no mismatch in window packet, management, subtype-12 Deauth counts, or
source-label sets. This validates feature aggregation, not classifier
performance.

## Limitations and next steps

- Recover original capture/session identities or obtain independently
  identified captures.
- Prepare a defensible split with Normal and Deauth-labelled windows in each
  partition; do not use a random split across neighboring times as a shortcut.
- AWID3 row labels do not by themselves define a validated flood episode.
- No monitor-mode capture, real-time analysis, packet injection, blocking, or
  network disruption is implemented.
- Add screenshots and genuine evaluation only after a valid experiment.

## Screenshot placeholders

- `[Insert screenshot: dashboard showing dataset, selected columns and labels]`
- `[Insert screenshot: preparation manifest and audit summary]`
- `[No confusion-matrix screenshot: no valid AWID3 model was trained]`

## References and disclosure

- AWID3 source/version and access terms: cite the exact dataset documentation
  recorded in `reports/awid3_inspection_report.md` and follow its license.
- Implementation assistance: disclose tool use according to course rules;
  student reviews and owns the final analysis and presentation.
