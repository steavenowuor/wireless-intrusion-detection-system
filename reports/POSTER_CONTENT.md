# A1 Poster Content: Offline Wireless Intrusion Detection with AWID3

## Problem

Wireless denial-of-service activity can generate abnormal management-frame patterns. This project demonstrates an offline machine-learning workflow for identifying one-second windows that contain AWID3 rows labelled Deauth.

## Objective

Build a reproducible, student-explainable AWID3 CSV prototype with window-level feature summaries, a Decision Tree baseline, transparent evaluation, and a Streamlit inference interface.

## Dataset and target

- AWID3 CSV Deauth sequence: `Deauth_0.csv`–`Deauth_32.csv`.
- 1,626,469 source rows → 604 one-second windows.
- Window distribution: **424 Normal (70.2%)**, **180 Deauth-containing (29.8%)**.
- All 180 Deauth-containing windows are mixed windows with Normal and Deauth source rows.
- Window label: Deauth if at least one source packet row has `Label=Deauth`; otherwise Normal.
- Source chunks are strongly corroborated as one ordered sequence. Original pcap filename is not established.

## Method and architecture

```text
AWID3 CSV chunks
      ↓ bounded chunk reads; frame.number order; preserve epoch timestamps
One-second window aggregation + provenance manifest
      ↓ curated numeric summaries; exclude labels, direct Deauth counts, IDs, time
Training-only sklearn pipeline → Decision Tree (seed 42)
      ↓ stratified exploratory 80/20 within-capture holdout
Metrics + confusion matrix + saved model → Streamlit offline CSV dashboard
```

Nine inputs: packet count, management-frame count, retry count/fraction, frame-length mean/max, signal mean/min, unique transmitter count. Source labels/counts, mixed indicator, Deauth frame count/rate/fraction, timestamps, frame numbers, filenames and capture identifiers are excluded.

## Results (exploratory only)

Train: **483 windows** (339 Normal, 144 Deauth). Test: **121 windows** (85 Normal, 36 Deauth).

| Metric | Decision Tree | Majority baseline |
|---|---:|---:|
| Accuracy | **0.9917** | 0.7025 |
| Precision | **1.0000** | 0.0000 |
| Recall | **0.9722** | 0.0000 |
| F1 | **0.9859** | 0.0000 |

Confusion matrix, actual × predicted (Normal, Deauth):

|  | Normal | Deauth |
|---|---:|---:|
| Normal | 85 | 0 |
| Deauth | 1 | 35 |

## Limitations

- Random window split comes from one capture sequence; neighboring windows may be correlated across train/test. These metrics do **not** establish independent-capture generalization.
- Original capture filename is unknown; CSV chunks are not independent sessions.
- Deauth labels identify source-label presence, not a verified flood episode or flood threshold.
- This is an **offline AWID3 CSV prototype**. It does not perform live packet capture, network monitoring, packet injection, disruption, or blocking.

## Conclusion and future work

The prototype demonstrates the full offline data-to-model workflow and an auditable baseline. Evaluate with independently identified capture sessions and ground-truth flood intervals before making generalization or flood-detection claims.

## References

- A. Kolias et al., “A large-scale wireless network dataset for intrusion detection systems,” [AWID3 dataset page](https://icsdweb.aegean.gr/awid/awid3). Cite the exact downloaded dataset edition and access terms used.
- This poster reports the saved local experiment at `models/awid3_deauth_baseline_20261031/metrics.json`.

## Poster production note

Arrange these sections as an A1 landscape poster. Render the architecture and confusion matrix legibly. Add a screenshot only from the actual running Streamlit app; do not invent a screenshot or replace the stated limitations.
