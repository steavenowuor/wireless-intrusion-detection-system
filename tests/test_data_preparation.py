"""Data-preparation behavior tests use tiny synthetic CSVs, never AWID3 data."""

import json

import pandas as pd
import pytest

from src.data_preparation import iter_awid3_windows, prepare_awid3_subset


def _synthetic_source(path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def test_synthetic_chunks_join_windows_and_keep_capture_group(tmp_path):
    first = _synthetic_source(tmp_path / "part_a.csv", {
        "Label": ["Normal", "Normal"],
        "frame.time_epoch": [10.1, 10.6],
        "wlan.fc.type": [0, 0], "wlan.fc.subtype": [0, 12],
    })
    second = _synthetic_source(tmp_path / "part_b.csv", {
        "Label": ["Deauth", "Normal"],
        "frame.time_epoch": [10.9, 11.1],
        "wlan.fc.type": [0, 2], "wlan.fc.subtype": [12, 0],
    })
    stats = {}
    windows = pd.concat(list(iter_awid3_windows(
        [first, second], "synthetic-source-capture", chunksize=1, stats=stats,
        capture_id_verified=True,
    )), ignore_index=True)
    assert windows["capture_id"].unique().tolist() == ["synthetic-source-capture"]
    assert windows["window_label"].tolist() == ["Deauth", "Normal"]
    assert windows["source_files"].tolist() == ["part_a.csv|part_b.csv", "part_b.csv"]
    assert windows.loc[0, "source_label_counts"] == '{"Deauth": 1, "Normal": 2}'
    assert windows["mixed_window"].tolist() == [True, False]
    assert windows["packet_count"].tolist() == [3, 1]
    assert stats["rows_read"] == 4
    assert stats["windows_written"] == 2
    assert stats["source_row_label_counts"] == {"Normal": 3, "Deauth": 1}


def test_synthetic_frame_ordered_sequence_keeps_timestamp_regression_across_chunks_and_files(tmp_path):
    first = _synthetic_source(tmp_path / "part_0.csv", {
        "Label": ["Normal", "Normal"], "frame.number": [1, 2],
        "frame.time_epoch": [10.9, 10.8],
    })
    second = _synthetic_source(tmp_path / "part_1.csv", {
        "Label": ["Deauth", "Normal"], "frame.number": [3, 4],
        "frame.time_epoch": [10.7, 11.1],
    })
    stats = {}
    windows = pd.concat(list(iter_awid3_windows(
        [first, second], "synthetic-frame-sequence", chunksize=1, stats=stats,
        frame_ordered_sequence=True, max_timestamp_lateness_seconds=0.5,
    )), ignore_index=True)

    assert windows["window_start_epoch"].tolist() == [10.0, 11.0]
    assert windows.loc[0, "window_label"] == "Deauth"
    assert bool(windows.loc[0, "mixed_window"]) is True
    assert windows.loc[0, "source_label_counts"] == '{"Deauth": 1, "Normal": 2}'
    assert windows.loc[0, "source_files"] == "part_0.csv|part_1.csv"
    assert windows.loc[0, "source_time_epoch_first"] == pytest.approx(10.9)
    assert windows.loc[0, "source_time_epoch_last"] == pytest.approx(10.7)
    assert windows.loc[0, "source_time_epoch_min"] == pytest.approx(10.7)
    assert windows.loc[0, "source_time_epoch_max"] == pytest.approx(10.9)
    assert windows.loc[0, "timestamp_backward_movement_count"] == 2
    assert windows.loc[0, "source_frame_number_first"] == 1
    assert windows.loc[0, "source_frame_number_last"] == 3
    assert stats["timestamp_backward_movement_count"] == 2
    assert stats["timestamp_backward_max_seconds"] == pytest.approx(0.1)
    assert stats["timestamp_boundary_movements"][0]["backward_movement"] is True
    assert stats["frame_number_min"] == 1
    assert stats["frame_number_max"] == 4
    assert stats["frame_number_gap_transitions"] == 0
    assert stats["frame_numbers_missing_in_gaps"] == 0
    assert stats["windows_join_across_files"] is True
    assert stats["capture_id_verified"] is False
    assert stats["capture_id_status"] == "strongly_corroborated_frame_ordered_sequence_not_pcap_id"
    assert stats["mixed_window_count"] == 1


def test_synthetic_frame_ordered_sequence_records_frame_number_gaps(tmp_path):
    source = _synthetic_source(tmp_path / "with_gap.csv", {
        "Label": ["Normal", "Normal", "Deauth"],
        "frame.number": [1, 3, 4],
        "frame.time_epoch": [1.1, 1.2, 1.3],
    })
    stats = {}
    list(iter_awid3_windows([source], "synthetic", chunksize=2, stats=stats,
                            frame_ordered_sequence=True))
    assert stats["frame_number_gap_transitions"] == 1
    assert stats["frame_numbers_missing_in_gaps"] == 1


def test_synthetic_sequence_manifest_records_per_file_provenance_and_time(tmp_path):
    first = _synthetic_source(tmp_path / "part_0.csv", {
        "Label": ["Normal"], "frame.number": [10], "frame.time_epoch": [10.9],
    })
    second = _synthetic_source(tmp_path / "part_1.csv", {
        "Label": ["Deauth"], "frame.number": [11], "frame.time_epoch": [10.8],
    })
    output = tmp_path / "sequence.csv"
    manifest = prepare_awid3_subset(
        [first, second], output, "synthetic-sequence", chunksize=1,
        frame_ordered_sequence=True, max_timestamp_lateness_seconds=0.5,
    )
    saved = json.loads((tmp_path / "sequence.csv.manifest.json").read_text())
    assert manifest["rows_read"] == saved["rows_read"] == 2
    assert len(saved["source_files"]) == 2
    assert saved["frame_number_ranges_by_file"][str(first)]["first_frame_number"] == 10
    assert saved["frame_number_ranges_by_file"][str(second)]["last_frame_number"] == 11
    assert saved["timestamp_ranges_by_file"][str(second)]["first_valid_epoch_in_packet_order"] == pytest.approx(10.8)
    assert saved["timestamp_backward_movement_count"] == 1
    assert saved["capture_group_confidence"] == "strongly_corroborated_sequence"


def test_synthetic_frame_ordered_sequence_rejects_frame_number_reset(tmp_path):
    first = _synthetic_source(tmp_path / "part_0.csv", {
        "Label": ["Normal", "Normal"], "frame.number": [10, 11],
        "frame.time_epoch": [10.1, 10.2],
    })
    second = _synthetic_source(tmp_path / "part_1.csv", {
        "Label": ["Deauth"], "frame.number": [1],
        "frame.time_epoch": [10.3],
    })
    with pytest.raises(ValueError, match="frame.number moves backward or repeats"):
        list(iter_awid3_windows([first, second], "synthetic", chunksize=1,
                                frame_ordered_sequence=True))


def test_synthetic_frame_ordered_sequence_rejects_timestamp_reset_without_rewriting(tmp_path):
    source = _synthetic_source(tmp_path / "reset.csv", {
        "Label": ["Normal", "Deauth"], "frame.number": [1, 2],
        "frame.time_epoch": [10.9, 8.0],
    })
    stats = {}
    with pytest.raises(ValueError, match="Timestamp reset/backward movement"):
        list(iter_awid3_windows(
            [source], "synthetic", chunksize=2, stats=stats,
            frame_ordered_sequence=True, max_timestamp_lateness_seconds=1.0,
        ))
    assert stats["timestamp_reset_count"] == 1
    assert stats["timestamp_backward_movement_count"] == 1


def test_synthetic_preparation_writes_manifest_and_refuses_overwrite(tmp_path):
    source = _synthetic_source(tmp_path / "input.csv", {
        "Label": ["Normal", "Deauth"],
        "frame.time_epoch": [20.1, 20.2],
        "wlan.fc.type": [0, 0], "wlan.fc.subtype": [0, 12],
    })
    output = tmp_path / "prepared.csv"
    result = prepare_awid3_subset([source], output, "synthetic-capture", chunksize=1)
    data = pd.read_csv(output)
    manifest = json.loads((tmp_path / "prepared.csv.manifest.json").read_text())
    assert len(data) == 1
    assert data.loc[0, "window_label"] == "Deauth"
    assert data.loc[0, "source_labels"] == "Deauth|Normal"
    assert result["rows_read"] == manifest["rows_read"] == 2
    assert manifest["source_row_label_counts"] == {"Normal": 1, "Deauth": 1}
    assert manifest["capture_id_status"] == "unverified_group_tag"
    with pytest.raises(FileExistsError):
        prepare_awid3_subset([source], output, "synthetic-capture")


def test_synthetic_row_cap_reports_partial_and_unstarted_files(tmp_path):
    first = _synthetic_source(tmp_path / "first.csv", {
        "Label": ["Normal", "Normal"], "frame.time_epoch": [1.1, 1.2],
        "frame.len": [100, 120], "wlan_radio.signal_dbm": [-40, -41],
    })
    second = _synthetic_source(tmp_path / "second.csv", {
        "Label": ["Deauth", "Deauth"], "frame.time_epoch": [1.3, 2.1],
        "frame.len": [130, 140], "wlan_radio.signal_dbm": [-42, -43],
    })
    third = _synthetic_source(tmp_path / "third.csv", {
        "Label": ["Normal"], "frame.time_epoch": [3.1], "frame.len": [150],
    })
    stats = {}
    windows = pd.concat(list(iter_awid3_windows(
        [first, second, third], "provisional-series-tag", chunksize=1,
        max_rows=3, stats=stats,
    )), ignore_index=True)
    assert stats["rows_read"] == 3
    assert stats["row_cap_reached"] is True
    assert stats["source_rows_truncated"] is True
    assert stats["files_completed"] == [str(first)]
    assert stats["files_partially_read"] == [str(second)]
    assert stats["files_not_started"] == [str(third)]
    assert stats["rows_read_by_file"] == {str(first): 2, str(second): 1}
    assert windows["source_files"].tolist() == ["first.csv", "second.csv"]
    assert windows["window_label"].tolist() == ["Normal", "Deauth"]


def test_unverified_synthetic_files_are_not_joined_into_one_time_window(tmp_path):
    first = _synthetic_source(tmp_path / "first.csv", {
        "Label": ["Normal"], "frame.time_epoch": [1.1],
    })
    second = _synthetic_source(tmp_path / "second.csv", {
        "Label": ["Deauth"], "frame.time_epoch": [1.2],
    })
    stats = {}
    windows = pd.concat(list(iter_awid3_windows(
        [first, second], "unverified-series-tag", chunksize=1, stats=stats
    )), ignore_index=True)
    assert windows["source_files"].tolist() == ["first.csv", "second.csv"]
    assert windows["window_label"].tolist() == ["Normal", "Deauth"]
    assert stats["windows_join_across_files"] is False
    assert stats["capture_id_status"] == "unverified_group_tag"


def test_synthetic_exact_file_boundary_cap_reports_selected_files_not_started(tmp_path):
    first = _synthetic_source(tmp_path / "first.csv", {
        "Label": ["Normal", "Normal"], "frame.time_epoch": [1.1, 1.2],
    })
    second = _synthetic_source(tmp_path / "second.csv", {
        "Label": ["Deauth"], "frame.time_epoch": [2.1],
    })
    stats = {}
    list(iter_awid3_windows([first, second], "series-tag", chunksize=2,
                            max_rows=2, stats=stats))
    assert stats["row_cap_reached"] is True
    assert stats["files_completed"] == [str(first)]
    assert stats["files_not_started"] == [str(second)]
    assert stats["source_rows_truncated"] is True


def test_synthetic_row_cap_status_is_recorded_when_all_accepted_times_are_invalid(tmp_path):
    source = _synthetic_source(tmp_path / "invalid.csv", {
        "Label": ["Normal", "Deauth"], "frame.time_epoch": ["bad", ""],
    })
    stats = {}
    assert list(iter_awid3_windows([source], "series-tag", chunksize=2,
                                   max_rows=2, stats=stats)) == []
    assert stats["row_cap_reached"] is True
    assert stats["rows_read"] == 2
    assert stats["files_completed"] == [str(source)]


def test_synthetic_manifest_counts_missing_and_out_of_range_source_values(tmp_path):
    source = _synthetic_source(tmp_path / "measurements.csv", {
        "Label": ["Normal", "Normal", "Deauth"],
        "frame.time_epoch": [1.1, 1.2, 1.3],
        "frame.len": [3192, "--", -1],
        "radiotap.dbm_antsignal": [-140, "", -90],
        "wlan_radio.signal_dbm": [-40, None, -45],
    })
    result = prepare_awid3_subset([source], tmp_path / "prepared.csv",
                                  "series-tag", chunksize=2)
    diagnostics = result["raw_field_diagnostics"][str(source)]
    assert diagnostics["frame.len"]["values_above_2346_count"] == 1
    assert diagnostics["frame.len"]["out_of_field_range_count"] == 1
    assert diagnostics["frame.len"]["dash_tokens"]["--"] == 1
    assert diagnostics["radiotap.dbm_antsignal"]["out_of_field_range_count"] == 1
    assert diagnostics["radiotap.dbm_antsignal"]["missing_or_blank_count"] == 1
    assert diagnostics["wlan_radio.signal_dbm"]["missing_or_blank_count"] == 1


def test_synthetic_invalid_times_count_and_backwards_time_rejected(tmp_path):
    source = _synthetic_source(tmp_path / "invalid.csv", {
        "Label": ["Normal", "Normal"], "frame.time_epoch": ["bad", 1.0],
    })
    stats = {}
    windows = list(iter_awid3_windows([source], "synthetic", stats=stats))
    assert stats["invalid_timestamp_rows_skipped"] == 1
    assert sum(map(len, windows)) == 1

    backwards = _synthetic_source(tmp_path / "backwards.csv", {
        "Label": ["Normal", "Normal"], "frame.time_epoch": [2.0, 1.0],
    })
    with pytest.raises(ValueError, match="move backwards"):
        list(iter_awid3_windows([backwards], "synthetic", chunksize=2))


def test_synthetic_missing_required_columns_rejected(tmp_path):
    source = _synthetic_source(tmp_path / "wrong.csv", {"Label": ["Normal"]})
    with pytest.raises(ValueError, match="frame.time_epoch"):
        list(iter_awid3_windows([source], "synthetic"))
