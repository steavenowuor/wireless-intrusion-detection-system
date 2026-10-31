# AWID3 dataset inspection report

## Scope
Read-only inspection of the external local AWID3 dataset; the original dataset was not modified. CSV metadata was inventoried recursively. Label scans used pandas chunks with only the `Label` column selected; schema/missing-value samples used at most 10,000 rows per file. No training was run and no performance metrics were generated.

## Inventory
- 745 CSV files; 46,148,607,025 bytes (about 42.98 GiB).
- `1.Deauth`: 33 files, 1.83 GiB; `2.Disas`: 41 files, 2.21 GiB. This differs from the approximate 31/39 supplied in the request.
- No folder or filename identified a separate normal/benign category. Normal rows are included in attack-capture CSVs.
- Full file-by-file relative path, category, byte size, and MiB size: `awid3_csv_inventory.csv`.

## Dataset README and schema
Local `archive/read_me.pdf` states that the CSVs contain 254 fields (253 extracted features plus `Label`), were divided into chunks of 50,000 rows, and include normal background rows as well as manually labelled malicious rows. It reports 30,387,099 Normal and 6,526,404 malicious records across the listed categories. Its Deauth totals are 1,587,527 Normal / 38,942 malicious, and Disas totals are 1,938,585 Normal / 75,131 malicious. These are README-reported totals, not a fresh full-file recount.

The sampled Deauth and Disas schemas each had 254 columns and matched. They include frame length/number/timing, radiotap signal and channel fields, WLAN type/subtype/retry/reason code, WLAN addresses/sequence, and many higher-layer protocol fields. The complete observed header list is in `awid3_awid3_schema.txt`. No explicit capture/session ID column was found. `frame.number` and timestamps identify packet order/time, not an independent capture. Category directory plus filename stem/index appears to identify chunk provenance; the README describes 50,000-row splitting, so chunks from one category must not automatically be treated as independent captures.

## Sample inspection
The following are local file sizes; sample missingness is over the first 10,000 parsed rows, while full-file label counts are from chunked Label-only scans:

| File | Size | Full parsed rows and labels | First 10,000 labels | Missing sample cells / columns |
|---|---:|---|---|---:|
| `1.Deauth/Deauth_0.csv` | 38,582,340 bytes | 50,000; Normal 50,000 | Normal 10,000 | 2,103,003 / 220 |
| `1.Deauth/Deauth_21.csv` | 49,575,507 bytes | 50,000; Normal 49,115, Deauth 885 | Normal 10,000 | 2,103,666 / 220 |
| `2.Disas/Disas_0.csv` | 35,680,344 bytes | 50,000; Normal 50,000 | Normal 10,000 | 2,111,004 / 220 |
| `2.Disas/Disas_28.csv` | 56,920,173 bytes | 50,000; Normal 47,881, Disas 2,119 | Normal 9,439, Disas 561 | 2,089,784 / 220 |

The first Deauth chunk with a non-Normal label in the scanned sequence was `Deauth_21`; first such Disas chunk was `Disas_28`. No missing labels occurred in these scanned chunks. In `Deauth_0`, `Deauth_21`, and `Disas_0`, 220 of the 254 columns had at least one missing value in the 10,000-row sample; 8 fields were entirely missing in each sample. The exact fields with the most missing values vary by sample. Missing values are expected for protocol-specific fields; the preprocessing needs to handle them without turning missing into a class signal inadvertently.

## Compatibility and recommended next step
Current `src/train_model.py` accepts one already-loaded DataFrame, performs row-level binary classification, and can preserve source labels for a separate multiclass classifier. It recognizes `Normal` as 0 and other non-empty labels as malicious; the original `Label` can distinguish Deauth. Its optional group split requires an actual group column, which this CSV schema does not provide. Passing a filename chunk as the group would create false independence because adjacent chunk files may be from the same capture.

The current loader reads a whole CSV into memory; training has no chunked sampler or window-level feature builder. It can be used experimentally with a small prepared table, but it is not a safe turnkey path for these files. It also classifies individual labelled rows; it does not aggregate deauthentication management-frame rates into time windows, so it cannot substantiate a deauthentication-flood detector as such.

Recommended plan: (1) obtain/confirm source PCAP or session boundaries and map every chunk to its parent capture; (2) select a documented, deterministic, bounded set of Normal and Deauth rows from one or more captures, keeping a source-capture ID in a sidecar/group field; (3) build short time-window features from `frame.time_epoch` and WLAN management-frame type/subtype, with explicit handling for missing values and identifiers; (4) split by independent capture/session groups before fitting preprocessing; (5) report binary metrics plus Deauth-specific metrics and confusion matrix. The inspected local schema and README do not establish multiple independent Deauth captures, so a held-out-capture Deauth test cannot yet be assumed possible. If only one Deauth capture is available, report this limitation and use a temporally separated holdout as a weaker within-capture experiment, not as independent-capture validation.

No project code was changed. Implementing the bounded sampler, group metadata, window feature extraction, and corresponding evaluator would require substantive code changes and should wait for user approval.
