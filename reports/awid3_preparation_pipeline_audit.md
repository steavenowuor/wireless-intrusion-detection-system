# AWID3 preparation pipeline audit

## Scope

This audit covers offline CSV preparation and window feature extraction for the
locally inspected Deauth files 21–32. It does not train or evaluate a model.
The external local source dataset was read only and was not modified.

## Confirmed findings

- The existing `awid3_prepared_windows_21_32.csv` manifest documents that only
  `Deauth_21.csv` was started: the global 50,000-row cap was reached before the
  later requested files. It contains 12 windows (7 Normal, 5 Deauth), produced
  from 49,115 Normal and 885 Deauth source rows. The original prepared file was
  preserved.
- AWID3's local README describes 253 extracted fields plus `Label`. The source
  schema does not supply a capture/session identifier. The local README and
  split script do not establish that numbered chunks are separate captures or
  that they form one continuous capture.
- In the inspected Deauth 21–32 source rows (576,472 total), `frame.time_epoch`
  parsed and is treated as Unix epoch seconds. Windows use fixed intervals
  `[start, start + duration)`. The code enforces nondecreasing timestamps per
  file and carries a pending window between reader chunks. Unless provenance is
  explicitly verified, it flushes at each file boundary and does not join
  windows across files.
- For the selected rows, `wlan_radio.signal_dbm` is present and within the
  signed 8-bit range (-84 to -27 dBm). `radiotap.dbm_antsignal` has 221,975
  values outside its documented signed 8-bit representation, including the
  values that caused the previous -140 to -150 dBm aggregates. The dataset
  documentation does not identify these outliers as a particular sentinel;
  the preparer now rejects values outside the field's representable range and
  prefers the valid `wlan_radio.signal_dbm` field.
- `frame.len` is present and parseable throughout the inspected rows; observed
  range is 70–3,192 bytes, with 241 values above 2,346. Wireshark defines this
  field as an unsigned 32-bit value. No AWID3 documentation inspected here
  establishes 3,192 as missing, so the preparer retains it rather than
  imposing an unsupported 2,346-byte cutoff. Source capture files would be
  needed to investigate the physical origin of unusual frame sizes.
- In Deauth-labelled rows across the inspected selection, 38,893 use WLAN type
  0/subtype 12 and 49 use type 0/subtype 10. There are also 3 Normal-labelled
  rows with type 0/subtype 12. Wireshark maps these to deauthentication and
  disassociation management-frame subtypes respectively. The feature count is
  based on the observed frame fields, while target labels remain based on the
  source `Label` column.
- A window containing any malicious source label is labelled malicious. A
  Deauth-labelled row takes the Deauth subtype label for the window; mixed
  source labels and their counts remain in the prepared output for inspection.
  This label rule does not by itself establish that a window is a flood.

## Changes made

- `src/feature_extraction.py`: robust numeric parsing for `frame.len` and
  signal fields; prefer `wlan_radio.signal_dbm`; reject out-of-domain signed
  radiotap values; keep valid large unsigned frame lengths.
- `src/data_preparation.py`: truthful capture-ID verification status; no
  cross-file window joining for unverified IDs; per-file signal/frame
  diagnostics; per-file row and completion status; global row-cap reporting,
  including files not started and partial final input.
- `app.py`: labels the dashboard as an offline AWID3 prototype, describes the
  group tag as unverified by default, and displays processed versus requested
  file status and row-cap warnings.
- Tests cover parsing, window boundaries, mixed labels, chunk and file limits,
  unverified file boundaries, and the Streamlit preparation controls.
- A separate corrected preparation output was written to
  `data/awid3_prepared_windows_21_32_signal_audit.csv`; the old output was not
  overwritten. This used the 12 selected source files, a 600,000-row global
  cap, 50,000-row processing chunks, and unverified provenance. All 12 files
  completed (576,472 rows); 198 windows were emitted because unverified file
  boundaries are kept separate. No model was trained.

## Remaining limitations

- The dataset's own documentation does not provide a verified capture/session
  identity for these chunks. The audit output therefore cannot support an
  independent-capture split; numbered filenames are not treated as proof.
- Out-of-range radiotap values are invalid under the field's signed 8-bit
  representation, but their precise origin (sentinel versus extraction or
  source-data issue) is not documented. No source pcap was used to resolve it.
- Large `frame.len` values are retained as valid field values, but their
  capture-level meaning cannot be verified from CSV alone.
- Source labels can be mixed within a one-second window. A Deauth label means
  the source labeled at least one row Deauth; it does not define a validated
  flood threshold or flood episode.
- Model training, preprocessing fit, capture-independent evaluation, and
  metrics remain unperformed.

## Re-run checks on Windows

From PowerShell in the project directory:

```powershell
# Run this from the project directory in PowerShell.
& .\.venv\Scripts\Activate.ps1
python -m pytest -q
python -m compileall -q src app.py
```

The audit run in this workspace completed with **31 passed**. Compilation also
completed successfully. These are software tests only; they are not AWID3
model-performance results.

## Field references

- [Wireshark radiotap fields](https://www.wireshark.org/docs/dfref/r/radiotap.html)
- [Wireshark WLAN radio fields](https://www.wireshark.org/docs/dfref/w/wlan_radio.html)
- [Wireshark frame fields](https://www.wireshark.org/docs/dfref/f/frame.html)
- [Wireshark IEEE 802.11 subtype definitions](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ieee80211.h)
