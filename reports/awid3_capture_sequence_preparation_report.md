# AWID3 Deauth sequence preparation report

## Result

Prepared the full local Deauth CSV sequence using bounded 50,000-row chunks,
in numeric file order, with no global row cap. The original AWID3 data and all
previous prepared datasets were left unchanged. The final output is
`data/awid3_deauth_capture_sequence_windows_v2.csv`; its JSON sidecar is the
preparation manifest.

The output has **604 rows and 29 columns**. It contains **424 Normal-only**
windows and **180 Deauth-containing** windows. All 180 Deauth-containing
windows are marked mixed because each includes at least one Normal row and at
least one Deauth row. Every `source_label_counts` value reconciles with the
manifest totals: **1,587,527 Normal** rows and **38,942 Deauth** rows across
**1,626,469** parsed packets. The sum of `packet_count` is also 1,626,469.

## Ordering, time, and provenance

- All 33 chunks were processed and completed; none were partial or unstarted.
- `frame.number` ranges from 1 to 1,626,472 in strict increasing order. Three
  frame numbers are missing; there are no repeated or backwards frame numbers.
- All timestamps parsed. Four backwards timestamp movements were observed,
  all at chunk boundaries; the largest was 0.346640 seconds. No movement
  exceeded the configured one-second lateness bound, so no reset was inferred
  or rejected. Original epoch values were not sorted or rewritten. The output
  stores each window's first, last, minimum, and maximum source epoch value;
  original per-packet timestamps remain in the source CSVs.
- Thirty-one windows reference more than one source filename, confirming that
  window aggregation crossed chunk boundaries. `source_files` preserves those
  names in packet sequence order.
- The manifest marks the group **strongly corroborated as one frame-ordered
  Deauth sequence**, while retaining that the original pcap filename is not
  explicitly established. This is one capture group and is not independent
  capture validation.

The binary window rule is `Deauth` when at least one source row in the bin is
labelled `Deauth`, otherwise `Normal`. `mixed_window`, `source_labels`, and
`source_label_counts` make mixed traffic visible. A Deauth-labelled window does
not, by itself, demonstrate a deauthentication flood.

## Field validation

Across the 1,626,469 source rows, `frame.len` had no blank, unparseable, or
out-of-uint32-range values; its observed range was 70–3,268 bytes. 550 values
were above 2,346 bytes. They are retained: `frame.len` represents the complete
captured frame length and the preparation code does not impose an assumed
802.11 MPDU maximum. `wlan_radio.signal_dbm` was parseable and within signed
int8 range on every row, with observed values from −89 to −27 dBm, and was
selected for all output signal summaries. In contrast,
`radiotap.dbm_antsignal` had 600,000 unparseable nonempty entries and 388,994
values outside signed int8 range; a bounded sample includes strings such as
`-34-37-34`, which are not scalar dBm values. It was not selected as fallback
for any row because the preferred `wlan_radio.signal_dbm` value was valid.
No missing/blank values were counted in these three source columns. This
validates the chosen signal field for this sequence, but does not establish
the exact semantics of every multi-value radiotap encoding.

## Code and documentation changes

- `src/data_preparation.py`: explicit frame-ordered sequence mode; strict
  frame-number ordering and gap accounting; bounded timestamp lateness with
  anomaly reporting; per-file frame/time ranges; cross-chunk window carry.
- `src/feature_extraction.py`: ordered source filenames, explicit mixed-window
  flag, original timestamp range/endpoints, frame-number endpoints, and
  timestamp backward-movement summaries.
- `src/verify_awid3_preparation.py`: validates source file/row/window counts,
  row-label reconciliation, mixed-window and binary label rules, and fixed
  half-open timestamp bounds.
- Tests added for chunk/file-boundary backsteps, frame-number order and gaps,
  reset rejection, manifest ranges, mixed labels, and verifier pass/fail cases.
- `data/README.md` and the traceable data investigation report document the
  command, provenance, output fields, and evaluation limitations.

## Verification

Full test suite: **38 passed**. Python compilation succeeded. The real-data
verification command returned `verified_counts_and_window_bounds` and
confirmed 33 source files, 1,626,469 source rows, 604 windows, 424 Normal,
180 Deauth, and 180 mixed windows.

Commands from PowerShell in the project directory:

```powershell
# Run this from the project directory in PowerShell.
& .\.venv\Scripts\Activate.ps1
python -m pytest -q
python -m compileall -q src app.py tests
```

The exact preparation and count-verification command is in `data/README.md`.
It refuses to overwrite an existing result; choose another new CSV name when
re-running. No model was trained and no performance metrics were calculated.

## Remaining limits

- The exact original pcap filename is not present in local metadata.
- The three missing `frame.number` values cannot be attributed to a particular
  extraction step with certainty, although the local README documents removal
  of malformed/overflow rows.
- The dataset provides one Deauth capture sequence here. This output cannot
  support independent-capture evaluation; obtain a second independently
  labelled Deauth capture before making generalization claims.
- A source Deauth label is not a verified flood-episode label or threshold.
