"""Bounded, explicit AWID3 CSV-to-window preparation helpers.

Only the paths passed by the caller are read. CSV rows are streamed in chunks;
the prepared output contains aggregated windows rather than the source rows.
AWID3 chunk filenames are not treated as independent captures. An unverified
group tag is allowed and is recorded as such in the manifest.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Iterator

import pandas as pd
import numpy as np

from .feature_extraction import (SIGNED_INT8_MAX, SIGNED_INT8_MIN, UINT32_MAX,
                                 extract_awid3_window_features, parse_numeric_field)

REQUIRED_COLUMNS = {"Label", "frame.time_epoch"}
OPTIONAL_COLUMNS = ["wlan.fc.type", "wlan.fc.subtype", "wlan.fc.retry", "frame.len",
                    "radiotap.dbm_antsignal", "wlan_radio.signal_dbm",
                    "wlan.fixed.reason_code", "wlan.ta", "wlan.sa", "frame.number"]


def _update_raw_field_diagnostics(file_diagnostics: dict, chunk: pd.DataFrame) -> None:
    """Accumulate missing, malformed, and field-range evidence per source file."""
    for column in ("frame.len", "radiotap.dbm_antsignal", "wlan_radio.signal_dbm"):
        if column not in chunk.columns:
            continue
        raw = chunk[column]
        text = raw.astype("string").str.strip()
        numeric = parse_numeric_field(raw)
        item = file_diagnostics.setdefault(column, {
            "rows_seen": 0, "missing_or_blank_count": 0,
            "unparseable_nonempty_count": 0, "out_of_field_range_count": 0,
            "values_above_2346_count": 0, "numeric_min": None, "numeric_max": None,
            "dash_tokens": {"-": 0, "--": 0},
        })
        item["rows_seen"] += len(raw)
        missing = raw.isna() | text.eq("")
        item["missing_or_blank_count"] += int(missing.sum())
        item["unparseable_nonempty_count"] += int((~missing & numeric.isna()).sum())
        for token in ("-", "--"):
            item["dash_tokens"][token] += int(text.eq(token).sum())
        observed = numeric.dropna()
        if not observed.empty:
            lo = float(observed.min())
            hi = float(observed.max())
            item["numeric_min"] = lo if item["numeric_min"] is None else min(item["numeric_min"], lo)
            item["numeric_max"] = hi if item["numeric_max"] is None else max(item["numeric_max"], hi)
        if column in {"radiotap.dbm_antsignal", "wlan_radio.signal_dbm"}:
            invalid_range = numeric.notna() & ~numeric.between(SIGNED_INT8_MIN, SIGNED_INT8_MAX)
        else:
            invalid_range = numeric.notna() & (
                ~numeric.between(0, UINT32_MAX) | numeric.mod(1).ne(0)
            )
            item["values_above_2346_count"] += int((numeric > 2346).sum())
        item["out_of_field_range_count"] += int(invalid_range.sum())


def _record_row_cap(counters: dict, reader, csv_paths: list[str | Path],
                    path_index: int, path_text: str, raw_chunk_rows: int,
                    rows_accepted_from_chunk: int) -> None:
    """Record accurately which selected inputs remain after the global cap."""
    counters["row_cap_reached"] = True
    current_file_partial = raw_chunk_rows > rows_accepted_from_chunk
    if not current_file_partial:
        try:
            extra_rows = next(reader)
        except StopIteration:
            extra_rows = None
        current_file_partial = extra_rows is not None and not extra_rows.empty
    if current_file_partial:
        counters["files_partially_read"].append(path_text)
        counters["file_statuses"][path_text] = "partial"
    else:
        counters["files_completed"].append(path_text)
        counters["file_statuses"][path_text] = "complete"
    unstarted = [str(Path(path)) for path in csv_paths[path_index + 1:]]
    counters["files_not_started"].extend(unstarted)
    counters["file_statuses"].update({path: "not_started" for path in unstarted})
    counters["source_rows_truncated"] = bool(current_file_partial or unstarted)


def iter_awid3_windows(csv_paths: list[str | Path], capture_id: str,
                       window_seconds: float = 1.0, chunksize: int = 50_000,
                       max_rows: int | None = None,
                       stats: dict | None = None,
                       capture_id_verified: bool = False,
                       frame_ordered_sequence: bool = False,
                       max_timestamp_lateness_seconds: float = 1.0) -> Iterator[pd.DataFrame]:
    """Yield aggregated window frames from explicitly selected source files.

    `csv_paths` are processed in the order supplied. By default, files are not
    joined unless `capture_id_verified` is true. `frame_ordered_sequence` is a
    separate, explicit mode for a corroborated source sequence: frame.number
    must increase across every row/file, while bounded timestamp regressions
    are retained and recorded. No timestamp is sorted or rewritten.
    """
    if not csv_paths:
        raise ValueError("Provide at least one CSV path; no directory-wide scan is implicit")
    if not capture_id or not capture_id.strip():
        raise ValueError("Provide a nonempty capture/session group tag; mark it verified only when provenance supports that")
    if chunksize < 1:
        raise ValueError("chunksize must be a positive integer")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite positive number")
    if max_rows is not None and max_rows < 1:
        raise ValueError("max_rows must be a positive integer when set")
    if not math.isfinite(max_timestamp_lateness_seconds) or max_timestamp_lateness_seconds < 0:
        raise ValueError("max_timestamp_lateness_seconds must be finite and nonnegative")
    if frame_ordered_sequence and capture_id_verified:
        raise ValueError("Use frame_ordered_sequence for corroborated frame ordering; do not also claim a verified original pcap ID")

    counters = stats if stats is not None else {}
    pending_limit = max(chunksize * 2, 50_000)
    join_files = bool(capture_id_verified or frame_ordered_sequence)
    requested_files = [str(Path(path)) for path in csv_paths]
    counters.update({"capture_id": capture_id,
                     "capture_id_verified": bool(capture_id_verified),
                     "capture_id_status": ("verified" if capture_id_verified else
                                            "strongly_corroborated_frame_ordered_sequence_not_pcap_id"
                                            if frame_ordered_sequence else "unverified_group_tag"),
                     "capture_group_confidence": ("strongly_corroborated_sequence" if frame_ordered_sequence else
                                                   "verified_id" if capture_id_verified else "unverified"),
                     "capture_provenance_note": (
                         "Files are joined as one ordered sequence based on frame.number continuity and the published AWID3 Deauth frame interval; original pcap filename is not explicitly established."
                         if frame_ordered_sequence else ""),
                     "frame_ordered_sequence": bool(frame_ordered_sequence),
                     "windows_join_across_files": join_files,
                     "source_files": [], "files_started": [], "files_completed": [],
                     "files_partially_read": [], "files_not_started": [],
                     "file_statuses": {}, "rows_read_by_file": {}, "rows_read": 0,
                     "invalid_timestamp_rows_skipped": 0, "windows_written": 0,
                     "window_seconds": window_seconds, "chunksize": chunksize,
                     "max_rows": max_rows, "max_pending_rows": pending_limit,
                     "row_cap_reached": False, "source_rows_truncated": False,
                     "partial_final_window_possible": False,
                     "requested_files": requested_files,
                     "window_label_counts": {}, "source_row_label_counts": {},
                     "mixed_window_count": 0,
                     "raw_field_diagnostics": {},
                     "frame_number_min": None, "frame_number_max": None,
                     "frame_number_missing_rows": 0, "frame_number_invalid_rows": 0,
                     "frame_number_gap_transitions": 0, "frame_numbers_missing_in_gaps": 0,
                     "frame_number_order_errors": 0,
                     "frame_number_ranges_by_file": {},
                     "timestamp_backward_movement_count": 0,
                     "timestamp_backward_max_seconds": 0.0,
                     "timestamp_reset_count": 0,
                     "timestamp_lateness_limit_seconds": max_timestamp_lateness_seconds,
                     "timestamp_ranges_by_file": {},
                     "timestamp_boundary_movements": [],
                     "timestamp_backward_movements_by_file": {},
                     "timestamp_order_policy": (
                         "Preserve source epoch values and packet order by frame.number; allow backward steps only within configured lateness, keep affected epoch bins pending, and record every movement."
                         if frame_ordered_sequence else "Require nondecreasing timestamps within each file; join only when capture_id_verified is true."),
                     "signal_dbm_selection_counts": {
                         "wlan_radio.signal_dbm": 0,
                         "radiotap.dbm_antsignal_fallback": 0,
                         "unavailable": 0,
                     }})
    pending = pd.DataFrame()
    previous_epoch = None
    max_seen_epoch = None
    previous_frame_number = None
    previous_file_path = None
    first_epoch_in_file = None
    first_frame_in_file = None
    rows_remaining = max_rows

    for path_index, raw_path in enumerate(csv_paths):
        path = Path(raw_path)
        if not path.is_file():
            raise FileNotFoundError(f"AWID3 CSV not found: {path}")
        header = pd.read_csv(path, nrows=0).columns.tolist()
        missing = REQUIRED_COLUMNS - set(header)
        if missing:
            raise ValueError(f"{path.name} is missing required column(s): {', '.join(sorted(missing))}")
        if frame_ordered_sequence and "frame.number" not in header:
            raise ValueError(f"{path.name} is missing required column 'frame.number' for frame-ordered sequence processing")
        columns = [column for column in ["Label", "frame.time_epoch", *OPTIONAL_COLUMNS]
                   if column in header]
        path_text = str(path)
        counters["files_started"].append(path_text)
        counters["rows_read_by_file"][path_text] = 0
        counters["raw_field_diagnostics"].setdefault(path_text, {})

        reader = pd.read_csv(path, usecols=columns, chunksize=chunksize,
                             low_memory=False, on_bad_lines="error", keep_default_na=False)
        file_rows_read = 0
        file_status = "complete"
        first_epoch_in_file = None
        first_frame_in_file = None
        for chunk in reader:
            raw_chunk_rows = len(chunk)
            if rows_remaining is not None:
                chunk = chunk.iloc[:rows_remaining]
                rows_remaining -= len(chunk)
            rows_accepted_from_chunk = len(chunk)
            counters["rows_read"] += len(chunk)
            file_rows_read += len(chunk)
            counters["rows_read_by_file"][path_text] = file_rows_read
            if chunk.empty:
                break
            if path_text not in counters["source_files"]:
                counters["source_files"].append(path_text)
            _update_raw_field_diagnostics(counters["raw_field_diagnostics"][path_text], chunk)
            if frame_ordered_sequence:
                frame_number = parse_numeric_field(chunk["frame.number"])
                valid_frame = frame_number.notna() & frame_number.ge(1) & frame_number.mod(1).eq(0)
                counters["frame_number_missing_rows"] += int(chunk["frame.number"].astype("string").str.strip().eq("").sum())
                counters["frame_number_invalid_rows"] += int((~valid_frame).sum())
                if not valid_frame.all():
                    raise ValueError(f"{path.name} contains missing, invalid, nonpositive, or nonintegral frame.number values")
                frame_array = frame_number.to_numpy(dtype="int64")
                differences = np.diff(frame_array)
                invalid_order = differences <= 0
                if invalid_order.any() or (previous_frame_number is not None and frame_array[0] <= previous_frame_number):
                    counters["frame_number_order_errors"] += int(invalid_order.sum()) + int(
                        previous_frame_number is not None and frame_array[0] <= previous_frame_number
                    )
                    raise ValueError("frame.number moves backward or repeats in the supplied source order")
                gap_differences = differences[differences > 1]
                if previous_frame_number is not None and frame_array[0] - previous_frame_number > 1:
                    counters["frame_number_gap_transitions"] += 1
                    counters["frame_numbers_missing_in_gaps"] += int(frame_array[0] - previous_frame_number - 1)
                counters["frame_number_gap_transitions"] += int(len(gap_differences))
                counters["frame_numbers_missing_in_gaps"] += int((gap_differences - 1).sum())
                counters["frame_number_min"] = int(frame_array[0]) if counters["frame_number_min"] is None else min(
                    counters["frame_number_min"], int(frame_array[0]))
                counters["frame_number_max"] = int(frame_array[-1]) if counters["frame_number_max"] is None else max(
                    counters["frame_number_max"], int(frame_array[-1]))
                if first_frame_in_file is None:
                    first_frame_in_file = int(frame_array[0])
                file_frame_range = counters["frame_number_ranges_by_file"].setdefault(path_text, {
                    "first_frame_number": None, "last_frame_number": None,
                    "minimum_frame_number": None, "maximum_frame_number": None,
                    "rows_checked": 0,
                })
                if file_frame_range["first_frame_number"] is None:
                    file_frame_range["first_frame_number"] = int(frame_array[0])
                file_frame_range["last_frame_number"] = int(frame_array[-1])
                file_frame_range["minimum_frame_number"] = (
                    int(frame_array.min()) if file_frame_range["minimum_frame_number"] is None else
                    min(file_frame_range["minimum_frame_number"], int(frame_array.min()))
                )
                file_frame_range["maximum_frame_number"] = (
                    int(frame_array.max()) if file_frame_range["maximum_frame_number"] is None else
                    max(file_frame_range["maximum_frame_number"], int(frame_array.max()))
                )
                file_frame_range["rows_checked"] += len(frame_array)
                previous_frame_number = int(frame_array[-1])
            radio_signal = (parse_numeric_field(chunk["wlan_radio.signal_dbm"])
                            if "wlan_radio.signal_dbm" in chunk else
                            pd.Series(np.nan, index=chunk.index, dtype="float64"))
            radiotap_signal = (parse_numeric_field(chunk["radiotap.dbm_antsignal"])
                               if "radiotap.dbm_antsignal" in chunk else
                               pd.Series(np.nan, index=chunk.index, dtype="float64"))
            radio_valid = radio_signal.between(SIGNED_INT8_MIN, SIGNED_INT8_MAX)
            radiotap_valid = radiotap_signal.between(SIGNED_INT8_MIN, SIGNED_INT8_MAX)
            fallback_valid = ~radio_valid & radiotap_valid
            counters["signal_dbm_selection_counts"]["wlan_radio.signal_dbm"] += int(radio_valid.sum())
            counters["signal_dbm_selection_counts"]["radiotap.dbm_antsignal_fallback"] += int(fallback_valid.sum())
            counters["signal_dbm_selection_counts"]["unavailable"] += int((~radio_valid & ~radiotap_valid).sum())
            for label, count in chunk["Label"].fillna("<MISSING>").astype(str).value_counts().items():
                key = str(label)
                counters["source_row_label_counts"][key] = (
                    counters["source_row_label_counts"].get(key, 0) + int(count)
                )
            chunk["_source_file"] = path.name
            epoch = parse_numeric_field(chunk["frame.time_epoch"])
            valid = epoch.notna() & epoch.ge(0)
            counters["invalid_timestamp_rows_skipped"] += int((~valid).sum())
            if frame_ordered_sequence:
                file_time_range = counters["timestamp_ranges_by_file"].setdefault(path_text, {
                    "first_valid_epoch_in_packet_order": None,
                    "last_valid_epoch_in_packet_order": None,
                    "minimum_epoch": None, "maximum_epoch": None,
                    "rows_seen": 0, "invalid_rows": 0,
                })
                file_time_range["rows_seen"] += len(epoch)
                file_time_range["invalid_rows"] += int((~valid).sum())
                values = epoch.loc[valid]
                if len(values):
                    if file_time_range["first_valid_epoch_in_packet_order"] is None:
                        file_time_range["first_valid_epoch_in_packet_order"] = float(values.iloc[0])
                    file_time_range["last_valid_epoch_in_packet_order"] = float(values.iloc[-1])
                    lo, hi = float(values.min()), float(values.max())
                    file_time_range["minimum_epoch"] = (
                        lo if file_time_range["minimum_epoch"] is None else
                        min(file_time_range["minimum_epoch"], lo)
                    )
                    file_time_range["maximum_epoch"] = (
                        hi if file_time_range["maximum_epoch"] is None else
                        max(file_time_range["maximum_epoch"], hi)
                    )
            chunk = chunk.loc[valid].copy()
            epoch = epoch.loc[valid]
            if chunk.empty:
                if rows_remaining == 0:
                    _record_row_cap(counters, reader, csv_paths, path_index,
                                    path_text, raw_chunk_rows,
                                    rows_accepted_from_chunk)
                    break
                continue
            if frame_ordered_sequence:
                valid_epoch_values = epoch.loc[valid]
                if len(valid_epoch_values):
                    first_current_epoch = float(valid_epoch_values.iloc[0])
                    if first_epoch_in_file is None:
                        first_epoch_in_file = first_current_epoch
                        if previous_epoch is not None:
                            movement = first_current_epoch - previous_epoch
                            counters["timestamp_boundary_movements"].append({
                                "previous_file": previous_file_path,
                                "current_file": path_text,
                                "previous_last_epoch": previous_epoch,
                                "current_first_epoch": first_current_epoch,
                                "delta_seconds": movement,
                                "backward_movement": movement < 0,
                            })
                    backward = pd.Series(0.0, index=chunk.index, dtype="float64")
                    prior = previous_epoch
                    file_backward_count = 0
                    for row_index, current in valid_epoch_values.items():
                        current_value = float(current)
                        if prior is not None and current_value < prior:
                            backward_seconds = prior - current_value
                            counters["timestamp_backward_movement_count"] += 1
                            counters["timestamp_backward_max_seconds"] = max(
                                counters["timestamp_backward_max_seconds"], backward_seconds
                            )
                            file_backward_count += 1
                            backward.loc[row_index] = backward_seconds
                            if backward_seconds > max_timestamp_lateness_seconds:
                                counters["timestamp_reset_count"] += 1
                                raise ValueError(
                                    f"Timestamp reset/backward movement of {backward_seconds:.6f}s exceeds "
                                    f"the configured {max_timestamp_lateness_seconds:.6f}s lateness; "
                                    "the sequence cannot be safely windowed without review"
                                )
                        prior = current_value
                    counters["timestamp_backward_movements_by_file"][path_text] = (
                        counters["timestamp_backward_movements_by_file"].get(path_text, 0) + file_backward_count
                    )
                    previous_epoch = float(valid_epoch_values.iloc[-1])
                    max_chunk_epoch = float(valid_epoch_values.max())
                    max_seen_epoch = max(max_seen_epoch, max_chunk_epoch) if max_seen_epoch is not None else max_chunk_epoch
                chunk["_timestamp_backward_seconds"] = backward
            else:
                if previous_epoch is not None and float(epoch.iloc[0]) < previous_epoch:
                    raise ValueError("Timestamps move backwards across supplied rows/files; verify capture order and identity")
                if not epoch.is_monotonic_increasing:
                    raise ValueError("Timestamps move backwards within a CSV chunk; verify capture ordering")
                previous_epoch = float(epoch.iloc[-1])
                chunk["_timestamp_backward_seconds"] = 0.0
            chunk["_window"] = np.floor(epoch / window_seconds).astype("int64")
            if not pending.empty:
                chunk = pd.concat([pending, chunk], ignore_index=True)
            if frame_ordered_sequence:
                watermark = max_seen_epoch - max_timestamp_lateness_seconds
                safe_to_emit = ((chunk["_window"] + 1) * window_seconds) <= (watermark + 1e-12)
                completed = chunk.loc[safe_to_emit].drop(columns="_window")
                pending = chunk.loc[~safe_to_emit].copy()
            else:
                max_window = int(chunk["_window"].max())
                completed = chunk.loc[chunk["_window"] < max_window].drop(columns="_window")
                pending = chunk.loc[chunk["_window"] == max_window].copy()
            if len(pending) > pending_limit:
                raise ValueError(
                    "A single time window exceeds the safe pending-row limit; "
                    "use a shorter window or smaller source chunks"
                )
            if not completed.empty:
                windows = extract_awid3_window_features(completed, capture_id, window_seconds)
                if not windows.empty:
                    counters["windows_written"] += len(windows)
                    for label, count in windows["window_label"].value_counts().items():
                        counters["window_label_counts"][label] = counters["window_label_counts"].get(label, 0) + int(count)
                    counters["mixed_window_count"] += int(windows["mixed_window"].sum())
                    yield windows
            if rows_remaining == 0:
                _record_row_cap(counters, reader, csv_paths, path_index,
                                path_text, raw_chunk_rows,
                                rows_accepted_from_chunk)
                break
        else:
            counters["files_completed"].append(path_text)
            counters["file_statuses"][path_text] = "complete"
        if frame_ordered_sequence:
            previous_file_path = path_text
        if rows_remaining == 0:
            break
        if not join_files:
            # Do not merge time windows across files when they have no verified
            # shared capture identity. Each file remains visible in provenance.
            if not pending.empty:
                windows = extract_awid3_window_features(
                    pending.drop(columns="_window"), capture_id, window_seconds
                )
                if not windows.empty:
                    counters["windows_written"] += len(windows)
                    for label, count in windows["window_label"].value_counts().items():
                        counters["window_label_counts"][label] = counters["window_label_counts"].get(label, 0) + int(count)
                    counters["mixed_window_count"] += int(windows["mixed_window"].sum())
                    yield windows
                pending = pd.DataFrame()
            previous_epoch = None

    if not pending.empty:
        windows = extract_awid3_window_features(
            pending.drop(columns="_window"), capture_id, window_seconds
        )
        if not windows.empty:
            counters["windows_written"] += len(windows)
            for label, count in windows["window_label"].value_counts().items():
                counters["window_label_counts"][label] = counters["window_label_counts"].get(label, 0) + int(count)
            counters["mixed_window_count"] += int(windows["mixed_window"].sum())
            yield windows
    counters["partial_final_window_possible"] = bool(counters["source_rows_truncated"])


def prepare_awid3_subset(csv_paths: list[str | Path], output_csv: str | Path,
                         capture_id: str, window_seconds: float = 1.0,
                         chunksize: int = 50_000, max_rows: int | None = None,
                         capture_id_verified: bool = False,
                         frame_ordered_sequence: bool = False,
                         max_timestamp_lateness_seconds: float = 1.0) -> dict:
    """Stream selected source rows into a documented window-feature CSV.

    Writes a JSON sidecar next to the output with source paths and row/window
    counts. Existing outputs are refused to prevent accidental replacement.
    """
    output_path = Path(output_csv)
    manifest_path = output_path.with_suffix(output_path.suffix + ".manifest.json")
    if output_path.exists() or manifest_path.exists():
        raise FileExistsError(f"Refusing to overwrite prepared output: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    counters: dict = {}
    first = True
    try:
        for windows in iter_awid3_windows(csv_paths, capture_id, window_seconds,
                                          chunksize, max_rows, counters,
                                          capture_id_verified, frame_ordered_sequence,
                                          max_timestamp_lateness_seconds):
            windows.to_csv(output_path, mode="w" if first else "a",
                           header=first, index=False)
            first = False
        if first:
            raise ValueError("No valid timestamped windows were prepared")
        counters["output_csv"] = str(output_path.resolve())
        counters["manifest"] = str(manifest_path.resolve())
        manifest_path.write_text(json.dumps(counters, indent=2), encoding="utf-8")
    except Exception:
        output_path.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise
    return counters


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Prepare selected offline AWID3 CSV chunks as time-window features")
    parser.add_argument("csv_paths", nargs="+", help="Explicit CSV paths, supplied in capture order")
    parser.add_argument("--output", required=True, help="New prepared CSV output path")
    parser.add_argument("--capture-id", required=True,
                        help="Group tag; use a provisional tag if original capture provenance is unknown")
    parser.add_argument("--capture-id-verified", action="store_true",
                        help="Mark the group ID verified from original capture/session provenance")
    parser.add_argument("--frame-ordered-sequence", action="store_true",
                        help="Explicitly process a corroborated single sequence using strictly increasing frame.number; original pcap filename may still be unknown")
    parser.add_argument("--max-timestamp-lateness-seconds", type=float, default=1.0,
                        help="Maximum backward timestamp movement tolerated in frame-ordered sequence mode; values are preserved and counted")
    parser.add_argument("--window-seconds", type=float, default=1.0)
    parser.add_argument("--chunksize", type=int, default=50_000)
    parser.add_argument("--max-rows", type=int,
                        help="Optional raw-row cap across the selected paths")
    args = parser.parse_args()
    result = prepare_awid3_subset(args.csv_paths, args.output, args.capture_id,
                                  args.window_seconds, args.chunksize, args.max_rows,
                                  args.capture_id_verified, args.frame_ordered_sequence,
                                  args.max_timestamp_lateness_seconds)
    print(json.dumps(result, indent=2))
