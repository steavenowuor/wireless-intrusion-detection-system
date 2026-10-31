# Dataset handling

Keep licensed or large source datasets outside the repository. The project
ignores files in `data/` by default. The AWID3 source directory is external to this project and is not copied or
modified by it.

## AWID3 format observed locally

The inspected CSVs have 254 columns: 253 extracted features and the target
column `Label`. Observed source values include `Normal`, `Deauth`, and `Disas`.
`Normal` maps to binary class 0; other non-empty labels map to malicious class
1. Dataset versions can differ, so inspect the actual headers and labels before
using another copy. The full observed schema and file inventory are in
`../reports/awid3_awid3_schema.txt` and
`../reports/awid3_csv_inventory.csv`.

The dataset README describes category selection CSVs split into 50,000-row
chunks; the local split script names a source such as `Deauth2Selection.csv`.
It does not explain the filename transformation from its `split_...` output to
the supplied `Deauth_0.csv` names. The CSV schema has no explicit capture or
session ID. Do not treat numbered chunks as independent captures. For the
local Deauth series only, frame-number ranges support one ordered capture
sequence; this is strongly corroborated by the published Deauth frame interval,
but the original pcap filename is not explicitly mapped. It is one capture
group and cannot support independent-capture validation.

## Bounded window preparation

Run `python -m src.data_preparation` with explicit input paths. It reads only
those CSVs, in the order supplied, using pandas chunks. The optional
`--max-rows` limits raw rows across all inputs. The output includes
`capture_id`, `capture_id_status`, `source_files`, `window_start_epoch`, window features,
`window_label`, `source_labels`, and `source_label_counts`. Provenance and
source-label fields are excluded from model features.

The verified time field is `frame.time_epoch` in Unix epoch seconds. Windows
are fixed, non-overlapping bins `[start, start + duration)` on this epoch timeline.
Missing, malformed,
negative, or infinite timestamps are counted and skipped. Rows must be in
nondecreasing time order within each file; when the capture/group ID is not
verified, each file is windowed separately so the code does not silently join
different files as one continuous session. Cross-file windows are joined only
when the user explicitly marks a shared capture ID verified. Within a file,
the pending final window is carried across CSV reader chunks and emitted once.
If a row cap truncates the selected inputs, the final window may be incomplete;
the sidecar manifest reports this. An unusually large pending window triggers
a safe error rather than unbounded memory growth.

Window features include packet and management-frame counts, WLAN type-0 /
subtype-12 Deauth count and rate, retry counts, frame length and signal
summaries, reason-code count, and unique transmitter count. Wireshark defines
`wlan.fc.type` and `wlan.fc.subtype` as numeric 802.11 fields; this pipeline
counts type 0 / subtype 12 as management deauthentication frames. For signal,
the preparer prefers `wlan_radio.signal_dbm`, then falls back to
`radiotap.dbm_antsignal` only when it is within the signed 8-bit field range.
Values outside that representable range are treated as invalid, not as a
confirmed sentinel code. `frame.len` is treated as an unsigned 32-bit integer;
the code does not reject a large value merely because it exceeds 2,346 bytes.
The manifest records missing, unparseable, out-of-range, and >2,346 counts for
these raw fields. In the inspected
50,000-row `Deauth_21.csv`, all timestamps parsed; 881 of 885 Deauth-labelled
rows had WLAN type 0/subtype 12, while 4 had type 0/subtype 10. The source
`Label` remains the evidence. The derived `window_label` is malicious if any
source row is malicious, and retains `Deauth` if a Deauth-labelled row occurs.
`source_labels` and `source_label_counts` retain the original row-label set and
counts for audit.

A Deauth-labelled window means the source labels at least one row in that
window as Deauth. It does not independently prove a flood episode. The project
does not invent a flood threshold or claim flood-detection performance without
a separate defensible flood label and evaluation procedure.

Earlier filewise preparation example for Deauth files 21–32. This sample keeps
file boundaries separate and is not the current full-sequence output:

```powershell
# Run this from the project directory in PowerShell.
& .\.venv\Scripts\Activate.ps1
$sourceDir = Read-Host "Path to your AWID3 1.Deauth CSV folder"
$files = 21..32 | ForEach-Object { Join-Path $sourceDir "Deauth_$_.csv" }
python -m src.data_preparation `
  @files `
  --capture-id "AWID3-Deauth-series-unverified" `
  --output ".\data\deauth_windows_filewise_sample.csv" `
  --window-seconds 1 `
  --chunksize 50000 `
  --max-rows 600000
Get-Content .\data\deauth_windows_filewise_sample.csv.manifest.json
Import-Csv .\data\deauth_windows_filewise_sample.csv |
  Group-Object window_label |
  Select-Object Name, Count


The capture ID above is a provisional group tag, not a verified original pcap
identity. The selected files total fewer than 600,000 rows, so the
cap is a safety bound. The manifest separately lists requested files, files
started, files completed, files partially read, files not started, and per-file
row counts. If the cap is reached, later files may be unprocessed; do not infer
that every selected file was consumed. Review this status and the field
diagnostics before training. The preparer refuses to overwrite an existing
output; choose a new output filename for another run. Preparation does not
train a model.

## Full Deauth sequence preparation

The local audit supports processing `Deauth_0.csv` through `Deauth_32.csv` as
one frame-ordered source sequence. The original pcap filename is not known, so
the output manifest records strongly corroborated sequence provenance rather
than a verified pcap identity. Sequence mode requires `frame.number` to be a
positive integer and strictly increasing in the supplied order. It records
frame-number gaps and rejects duplicates or backwards frame numbers. It does
not change source timestamps. Backward timestamp movements up to the selected
lateness limit are retained, counted, and recorded; larger resets stop the
preparation. Potentially affected epoch windows remain pending so rows from
both sides of a chunk boundary can enter the correct fixed bin.

Each output window stores exact first, last, minimum, and maximum source epoch
values, first and last frame numbers, timestamp backstep counts, source labels
and counts, ordered source filenames, and an explicit `mixed_window` flag. The
original CSV files remain authoritative for packet-level timestamps. A window
is labelled `Deauth` if any source row has `Label=Deauth`, otherwise `Normal`.
This is a source-label rule and does not prove a deauthentication flood.

PowerShell commands to reproduce the full preparation and count verification.
The command example uses a fresh rerun filename; the preparer refuses to
overwrite an existing CSV or manifest. Choose another new filename for each
additional run:

```powershell
# Run this from the project directory in PowerShell.
& .\.venv\Scripts\Activate.ps1
$sourceDir = Read-Host "Path to your AWID3 1.Deauth CSV folder"
$files = @(Get-ChildItem -LiteralPath $sourceDir -File -Filter "Deauth_*.csv" |
  Sort-Object { [int]($_.BaseName -replace '^Deauth_', '') } |
  ForEach-Object FullName)
if ($files.Count -ne 33) { throw "Expected 33 chunks, found $($files.Count)" }
$output = ".\data\awid3_deauth_capture_sequence_windows_rerun.csv"
if ((Test-Path -LiteralPath $output) -or
    (Test-Path -LiteralPath ($output + ".manifest.json"))) {
  throw "Refusing to overwrite $output"
}
python -m src.data_preparation @files `
  --output $output `
  --capture-id "AWID3-Deauth-sequence-frame-1-1626472" `
  --frame-ordered-sequence `
  --window-seconds 1 `
  --chunksize 50000 `
  --max-timestamp-lateness-seconds 1
python -m src.verify_awid3_preparation $output `
  --expected-files 33 `
  --expected-rows 1626469 `
  --expected-windows 604 `
  --expected-normal-windows 424 `
  --expected-deauth-windows 180 `
  --expected-mixed-windows 180
```

The expected values were measured from the current local AWID3 files. A
mismatch is a failed verification to investigate; do not change expected
counts to force a pass. This remains an offline CSV prototype, not live Wi-Fi
monitoring or proof of flood detection.
