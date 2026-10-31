"""Verify a prepared AWID3 window CSV against its sidecar and expected counts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


def verify_prepared_awid3(output_csv: str | Path, expected_files: int,
                          expected_rows: int, expected_windows: int,
                          expected_normal_windows: int,
                          expected_deauth_windows: int,
                          expected_mixed_windows: int) -> dict:
    """Raise ValueError on any mismatch; return a concise verified summary."""
    csv_path = Path(output_csv)
    manifest_path = csv_path.with_suffix(csv_path.suffix + ".manifest.json")
    if not csv_path.is_file():
        raise FileNotFoundError(f"Prepared CSV not found: {csv_path}")
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Preparation manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    frame = pd.read_csv(csv_path)
    errors: list[str] = []

    file_count = len(manifest.get("source_files", []))
    if file_count != expected_files:
        errors.append(f"source_files={file_count}, expected {expected_files}")
    if len(manifest.get("files_completed", [])) != expected_files:
        errors.append("not all requested source files are complete")
    if manifest.get("files_partially_read") or manifest.get("files_not_started"):
        errors.append("manifest reports partially read or unstarted source files")
    if manifest.get("rows_read") != expected_rows:
        errors.append(f"manifest rows_read={manifest.get('rows_read')}, expected {expected_rows}")
    if len(frame) != expected_windows:
        errors.append(f"output windows={len(frame)}, expected {expected_windows}")
    if frame.get("window_label", pd.Series(dtype="string")).value_counts().to_dict() != {
        "Normal": expected_normal_windows, "Deauth": expected_deauth_windows
    }:
        errors.append("window label distribution does not match expected Normal/Deauth counts")
    mixed_count = int(frame.get("mixed_window", pd.Series(dtype="bool")).fillna(False).astype(bool).sum())
    if mixed_count != expected_mixed_windows:
        errors.append(f"mixed windows={mixed_count}, expected {expected_mixed_windows}")
    if int(manifest.get("mixed_window_count", -1)) != expected_mixed_windows:
        errors.append("manifest mixed_window_count does not match expected count")
    if int(frame.get("packet_count", pd.Series(dtype="int64")).sum()) != expected_rows:
        errors.append("sum of window packet_count does not equal source rows processed")
    source_label_counts: dict[str, int] = {}
    try:
        for encoded in frame["source_label_counts"]:
            for label, count in json.loads(encoded).items():
                source_label_counts[label] = source_label_counts.get(label, 0) + int(count)
        if source_label_counts != manifest.get("source_row_label_counts"):
            errors.append("window source-label counts do not reconcile with the manifest")
        for row in frame.itertuples(index=False):
            row_counts = json.loads(row.source_label_counts)
            expected_label = "Deauth" if row_counts.get("Deauth", 0) > 0 else "Normal"
            if row.window_label != expected_label:
                errors.append("a window label does not follow the any-Deauth-row rule")
                break
            if bool(row.mixed_window) != (len(row_counts) > 1):
                errors.append("mixed_window does not agree with its preserved row labels")
                break
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"source-label evidence is missing or invalid: {exc}")
    if manifest.get("invalid_timestamp_rows_skipped") != 0:
        errors.append("invalid source timestamps were skipped")
    if manifest.get("frame_number_order_errors") != 0:
        errors.append("frame-number ordering errors were observed")
    if frame.empty or not {"source_time_epoch_min", "source_time_epoch_max",
                           "window_start_epoch", "window_seconds"}.issubset(frame.columns):
        errors.append("source timestamp summary columns are missing")
    elif not (
        (frame["source_time_epoch_min"] >= frame["window_start_epoch"]).all()
        and (frame["source_time_epoch_max"] <
             frame["window_start_epoch"] + frame["window_seconds"]).all()
    ):
        errors.append("source timestamps do not fit their fixed half-open windows")
    if errors:
        raise ValueError("AWID3 preparation verification failed: " + "; ".join(errors))

    return {
        "status": "verified_counts_and_window_bounds",
        "csv": str(csv_path.resolve()),
        "manifest": str(manifest_path.resolve()),
        "source_files": file_count,
        "source_rows": int(manifest["rows_read"]),
        "windows": len(frame),
        "window_label_counts": frame["window_label"].value_counts().to_dict(),
        "source_row_label_counts": source_label_counts,
        "mixed_windows": mixed_count,
        "frame_number_min": manifest.get("frame_number_min"),
        "frame_number_max": manifest.get("frame_number_max"),
        "frame_number_gap_transitions": manifest.get("frame_number_gap_transitions"),
        "frame_numbers_missing_in_gaps": manifest.get("frame_numbers_missing_in_gaps"),
        "timestamp_backward_movement_count": manifest.get("timestamp_backward_movement_count"),
        "timestamp_backward_max_seconds": manifest.get("timestamp_backward_max_seconds"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prepared_csv")
    parser.add_argument("--expected-files", type=int, required=True)
    parser.add_argument("--expected-rows", type=int, required=True)
    parser.add_argument("--expected-windows", type=int, required=True)
    parser.add_argument("--expected-normal-windows", type=int, required=True)
    parser.add_argument("--expected-deauth-windows", type=int, required=True)
    parser.add_argument("--expected-mixed-windows", type=int, required=True)
    args = parser.parse_args()
    result = verify_prepared_awid3(
        args.prepared_csv, args.expected_files, args.expected_rows,
        args.expected_windows, args.expected_normal_windows,
        args.expected_deauth_windows, args.expected_mixed_windows,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
