# AWID3 Normal/Deauth selection and provenance investigation

## Scope and method

The original local AWID3 dataset tree was read only. I inspected the local
AWID3 README PDF, the included label/split scripts, the existing inventory and
schema reports, and the official AWID3 project page. I scanned all 33
`1.Deauth\Deauth_*.csv` files with pandas chunks of 25,000 rows and only
`Label`, `frame.time_epoch`, and `frame.number`; the files were never
concatenated or loaded together. The existing prepared CSVs were not changed.

## Confirmed source and label findings

- The local AWID3 README says the CSV extraction contains 253 features plus
  `Label`, chunks were split at 50,000 rows, and rows were initially labelled
  Normal before malicious rows were separated manually. It reports 1,587,527
  Normal and 38,942 malicious rows for Deauth.
- The delivered tree has no standalone Normal category. Normal traffic is
  included in attack-category files. The actual `Label` values, rather than
  folder or filename alone, must be used.
- A complete bounded scan of `1.Deauth\Deauth_0.csv` through
  `Deauth_32.csv` found **1,626,469 rows**: **1,587,527 Normal** and
  **38,942 Deauth**. This exactly matches the local README's Deauth totals.
  Files `Deauth_0.csv`–`Deauth_20.csv` contain only Normal-labelled rows.
  Files `Deauth_21.csv`–`Deauth_32.csv` contain both Normal and Deauth rows.
  In particular, an attack-named file is not all malicious.
- The timestamp range is 1608306178.4826–1608306781 Unix seconds. Timestamps
  are nondecreasing within each file, but there are four small backward
  movements at file boundaries (largest about 0.347 s). Do not concatenate by
  timestamp with the current strict cross-file monotonicity check.

## Capture grouping evidence

The local CSVs have no explicit capture/session ID. However, `frame.number`
provides much stronger sequence evidence than the filenames alone:

- Chunk frame-number ranges abut in numeric order, from frame 1 through
  1,626,472. There are no duplicate or backward frame numbers; three frame
  numbers are absent inside the sequence. The local README notes that some
  malformed/overflow rows were removed, which is consistent with—but does not
  prove the cause of—those gaps.
- The official AWID3 page publishes the Deauth Wireshark filter range
  `frame.number >= 1088022 && frame.number <= 1626254`. The 38,942 observed
  Deauth-labelled rows have minimum and maximum frame numbers exactly 1,088,022
  and 1,626,254, respectively, and every Deauth-labelled row is within that
  range. This strongly corroborates that these numbered chunks are one ordered
  Deauth capture sequence, rather than independent captures.
- The exact original pcap filename is not present in the local CSV directory,
  so the manifest records the group as strongly corroborated, not as a pcap
  filename verified from a sidecar. This sequence is one capture group only;
  it cannot support independent-capture train/test validation.

The official page describes the filter as a way to discern attack traffic and
says the filters return the great majority of attack frames. The exact match
to the observed `Label=Deauth` frame-number endpoints is strong corroboration,
but it does not turn every row in that frame range into an attack row. The CSV
`Label` remains the row-level label.

## Window-level selection

If one-second epoch bins are aggregated over the ordered frame sequence,
carrying bins across chunk boundaries, the scan yields **604 unique bins**:

- 424 bins contain only Normal-labelled rows.
- 180 bins contain at least one Deauth-labelled row.
- All 180 Deauth-containing bins also contain Normal background rows.

Recommended binary window rule: label a bin Deauth/Malicious if it contains
any row whose original `Label` is `Deauth`; otherwise label it Normal. Preserve
the original row labels, per-window Normal/Deauth row counts, source filenames,
and a `mixed_label` flag. Under this rule the Deauth windows are mixed windows,
not pure attack-only windows. Their class is determined by the presence of a
Deauth-labelled row, not by the Deauth folder name or the proportion of
deauthentication frames.

This provides enough labelled windows for an exploratory balanced *training*
sample (180 Normal-only windows and all 180 Deauth-containing windows), but it
does not give a defensible evaluation split. The attack is temporally
concentrated: the Normal-only windows precede the Deauth-labelled interval.
A chronological holdout cannot put both labels in both train and test; a
random window split would mix adjacent periods from the same capture and
overstate generalization. Do not report independent-capture performance from
this source.

For a future valid evaluation, obtain at least one additional independently
captured Deauth session/pcap with documented labels and Normal background, and
retain capture/session identifiers. Split by capture before selecting or
balancing windows. If no second Deauth capture is available, use this sequence
for development only and report the absence of independent Deauth evaluation.

## Proposed source manifest

`awid3_deauth_candidate_manifest.csv` contains one row per source CSV with its
absolute path, size, full rows scanned / proposed row limit, source-label
counts, timestamp range, frame-number range, per-file one-second label counts,
and provenance status. It lists every chunk from `_0` to `_32`; no arbitrary
50,000-row global cap is proposed. Rows 8 and 9 have 49,999 and 49,998 parsed
rows respectively, consistent with the README's note that malformed rows
were removed.

Recommended source selection: the complete `1.Deauth\Deauth_0.csv` through
`Deauth_32.csv` sequence, preserving row labels and ordering by `frame.number`.
This is approximately 1.63 million rows, manageable with the existing 50,000
row streaming chunks. Do not treat the 33 CSVs as 33 capture groups. The
existing preparation code currently rejects the observed small timestamp
regressions if cross-file joining is enabled. Before preparing a new joined
window CSV, update that logic to order by `frame.number`, aggregate epoch bins
across chunk boundaries, and retain timestamp values unchanged. Do not mark a
window sequence as verified based only on its group-tag text.

## Exact next steps

1. Review `reports/awid3_deauth_candidate_manifest.csv` and this report.
2. Before generating any new prepared data, add and test a capture-sequence
   mode that uses the verified `frame.number` order and tolerates these
   measured cross-file timestamp regressions without sorting or changing raw
   timestamps. Keep the current and audit prepared datasets unchanged.
3. Prepare the complete 33-file sequence with 50,000-row processing chunks,
   no truncating row cap, and a new output name. Verify the resulting manifest
   reports all 33 files, 1,626,469 rows, the 604-bin / 424 Normal / 180 Deauth
   counts, and 180 mixed windows before any training is considered.
4. For evaluation, obtain and manifest a second independent Deauth capture.
   Do not use a random split of these windows as an independent-capture test.

No code changed, no new prepared window CSV was written, no model was trained,
and no performance metrics were calculated during this investigation.

## Implementation follow-up (2026-10-26)

The frame-ordered preparation path was subsequently implemented and run as
`data/awid3_deauth_capture_sequence_windows_v2.csv`. Its sidecar manifest
records all 33 source chunks, 1,626,469 rows, frame-number gaps, four backward
timestamp movements (largest 0.346640 seconds), and the strongly corroborated
sequence / unknown original pcap-name status. The output has 604 windows:
424 Normal-only and 180 Deauth-containing, with all 180 Deauth windows marked
mixed. A separate verifier checks these counts, window bounds, packet totals,
and source-label reconciliation. The software remains offline and no model was
trained.

## References

- Local source files: `archive/read_me.pdf` and
  `archive/code-features/label/label.py.py` within the dataset distribution.
- [Official AWID3 project page and Deauth frame-number filter](https://icsdweb.aegean.gr/awid/awid3)
- [AWID3 dataset paper](https://icsdweb.aegean.gr/awid/Empirical-evaluation-of-attacks-against-IEEE-802.11-enterprise-networks-The-AWID3-dataset.pdf)
