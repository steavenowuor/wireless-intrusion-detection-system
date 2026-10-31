# AWID3 bounded window audit

Date: 2026-10-26

## Scope and method

Only Deauth files `Deauth_21.csv` through `Deauth_32.csv` from the external
local AWID3 directory were used. The preparer streamed the 12 explicit paths in
50,000-row pandas chunks with a 600,000-row safety limit. It read 576,472 rows,
skipped zero invalid timestamps, reached no row cap, and emitted 187 aligned
one-second windows in a 45,519-byte CSV. The source CSVs were not changed.

An independent second pass read only `Label`, `frame.time_epoch`,
`wlan.fc.type`, and `wlan.fc.subtype` in chunks. It verified 576,472 rows,
nondecreasing timestamps, 187 distinct one-second bins, and exact per-window
agreement with the output for packet counts, management counts (`type == 0`),
Deauth-frame counts (`type == 0 and subtype == 12`), and source-label sets.
There were no aggregate mismatches. The verified timestamp range was
1608306595–1608306781 Unix epoch seconds.

## Observed counts

- Source row labels: Normal 537,530; Deauth 38,942.
- Derived window labels: Normal 7; Deauth 180.
- Packets across windows: 576,472.
- Management frames (`wlan.fc.type == 0`): 43,946.
- Deauthentication frames (`wlan.fc.type == 0` and `.subtype == 12`): 38,896.
- Observed Deauth frame rates: 0–310 per second.
- The seven Normal windows are the first seven bins; all 180 later bins contain
  one or more Deauth-labelled source rows. Many windows also contain Normal
  rows; the binary target is malicious when any source row is malicious.

The old `data/deauth_windows.csv` is preserved and was not used. It predates the
corrected schema and has an older sidecar; use
`data/deauth_windows_verified.csv` plus its sidecar for the audited run.

## Window logic and interpretation

`frame.time_epoch` values in the checked files are numeric Unix seconds and
were monotonic in supplied order. Fixed, non-overlapping bins are formed by
`floor(epoch / window_seconds)`. Fifty thousand source rows produced 12 bins
for `Deauth_21.csv` because the timestamps span 12 integer-second bins, not
because rows were lost. The pending final bin is carried across pandas chunks
and adjacent file boundaries, then emitted once at end of input. The corrected
manifest marks no truncation and no partial final window for the 576,472-row
run.

The window target `window_label` is derived from source `Label` rows. It is
`Normal` only when all rows in that bin are Normal/benign/0; any other source
label makes it malicious, retaining `Deauth` when present. The untouched source
label set and per-window counts are retained in `source_labels` and
`source_label_counts`. This target indicates a Deauth-labelled bin, not a
validated flood episode.

## Split decision

All 12 selected files are contiguous chunks from a documented category
selection series. The local CSV schema contains no original capture/session
identifier, so `AWID3-Deauth-series-unverified` is only a provisional shared
group tag. Chunk numbers are not treated as separate captures. The configured
chronological 80/20 split with a one-second purge places all seven Normal bins
before the Deauth interval; its test partition has no Normal class. The trainer
was run and stopped with:

`ValueError: Selected split does not contain both binary classes in train and test; choose a better group column or test_size`

No AWID3 model was fitted or saved, and no AWID3 metrics or confusion matrix
exist. A random row split would mix neighboring times from this same series
across partitions and would not repair the missing temporal class coverage.
This dataset subset cannot support a trustworthy two-class evaluation under
the documented leakage controls.

## Deauth and flood conclusion

The observed source Deauth label and management subtype features are verified
in the local sample. However, Deauth-specific classifier metrics are not
available because training did not proceed. The number of subtype 12 frames in
a time bin is a measured feature, not a ground-truth flood label. No flood
threshold or flood-detection performance is claimed.
