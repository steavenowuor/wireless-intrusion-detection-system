"""Software behavior tests using synthetic data only, not AWID3 measurements."""
import pandas as pd
import pytest

from src.feature_extraction import (extract_awid3_window_features,
                                    remove_obvious_leakage,
                                    parse_dbm_signal_fields,
                                    parse_frame_length_field,
                                    validate_feature_frame)
from src.data_loader import normalize_binary_labels, split_features_and_labels


def test_synthetic_feature_frame_is_copied_and_kept():
    synthetic = pd.DataFrame({"frame_length": [64, 128], "signal_dbm": [-45, None]})
    result = validate_feature_frame(synthetic)
    assert result.equals(synthetic)
    assert result is not synthetic


def test_label_column_is_not_returned_as_feature():
    synthetic = pd.DataFrame({"frame_length": [64, 128], "label": ["normal", "deauth"]})
    x, y, original = split_features_and_labels(synthetic, "label")
    assert list(x.columns) == ["frame_length"]
    assert y.tolist() == [0, 1]
    assert original.tolist() == ["normal", "deauth"]


def test_synthetic_label_values_and_missing_rejection():
    assert normalize_binary_labels(pd.Series(["normal", "deauthentication", "1"])).tolist() == [0, 1, 1]
    with pytest.raises(ValueError, match="missing"):
        normalize_binary_labels(pd.Series(["normal", None]))


def test_rejects_label_like_feature_name():
    with pytest.raises(ValueError, match="target/label"):
        validate_feature_frame(pd.DataFrame({"class": [0, 1], "length": [64, 128]}))


def test_synthetic_awid3_windows_count_management_deauth_and_preserve_label():
    synthetic = pd.DataFrame({
        "Label": ["Normal", "Deauth", "Normal", "Normal"],
        "frame.time_epoch": [100.1, 100.2, 100.8, 101.2],
        "wlan.fc.type": ["0x0", "0", "2", "0"],
        "wlan.fc.subtype": ["12", "0x0c", "0", "12"],
        "wlan.fc.retry": ["1", "0", "0", "1"],
        "frame.len": [24, 26, 100, 24],
        "radiotap.dbm_antsignal": [-40, None, -60, -42],
        "wlan.ta": ["aa", "bb", None, "aa"],
    })
    windows = extract_awid3_window_features(synthetic, "synthetic-capture", 1.0)
    assert len(windows) == 2
    first = windows.iloc[0]
    assert first["window_label"] == "Deauth"
    assert first["source_labels"] == "Deauth|Normal"
    assert first["capture_id"] == "synthetic-capture"
    assert first["packet_count"] == 3
    assert first["management_frame_count"] == 2
    assert first["deauth_frame_count"] == 2
    assert first["retry_frame_count"] == 1
    assert first["unique_transmitter_count"] == 2
    assert windows.iloc[1]["window_label"] == "Normal"


def test_synthetic_invalid_timestamps_are_skipped_and_missing_values_safe():
    synthetic = pd.DataFrame({
        "Label": ["Normal", "Deauth"],
        "frame.time_epoch": ["not-a-time", "200.1"],
        "wlan.fc.type": [None, "0"],
        "wlan.fc.subtype": [None, "12"],
        "frame.len": [None, "invalid"],
    })
    windows = extract_awid3_window_features(synthetic, "synthetic", 1.0)
    assert len(windows) == 1
    assert windows.iloc[0]["window_label"] == "Deauth"
    assert windows.iloc[0]["packet_count"] == 1
    assert windows.iloc[0]["deauth_frame_count"] == 1
    assert pd.isna(windows.iloc[0]["frame_len_mean"])


def test_group_and_time_fields_are_excluded_from_model_features():
    synthetic = pd.DataFrame({"capture_id": ["a"], "window_start_epoch": [10],
                              "wlan.ta": ["aa"], "source_labels": ["Normal"],
                              "source_files": ["part.csv"], "packet_count": [2]})
    safe, dropped = remove_obvious_leakage(synthetic)
    assert list(safe.columns) == ["packet_count"]
    assert set(dropped) == {"capture_id", "window_start_epoch", "wlan.ta",
                            "source_labels", "source_files"}
    assert len(dropped) == len(set(dropped))


def test_signal_prefers_wlan_radio_and_ignores_out_of_range_radiotap_values():
    index = pd.RangeIndex(4)
    preferred = pd.Series([-40, None, -200, -45], index=index)
    fallback = pd.Series([-90, -75, -140, -150], index=index)
    parsed = parse_dbm_signal_fields(preferred, fallback, index)
    assert parsed.iloc[0] == -40
    assert parsed.iloc[1] == -75
    assert pd.isna(parsed.iloc[2])
    assert parsed.iloc[3] == -45


def test_frame_length_keeps_large_uint32_value_and_treats_markers_as_missing():
    parsed = parse_frame_length_field(pd.Series(["3192", "--", "-1", "1.5", None]))
    assert parsed.iloc[0] == 3192
    assert parsed.iloc[1:].isna().all()


def test_window_signal_uses_valid_primary_and_fallback_values():
    synthetic = pd.DataFrame({
        "Label": ["Normal"] * 4,
        "frame.time_epoch": [10.1, 10.2, 10.3, 10.4],
        "frame.len": [3192, "--", 100, -1],
        "wlan_radio.signal_dbm": [-40, None, -200, -45],
        "radiotap.dbm_antsignal": [-90, -75, -140, -150],
    })
    window = extract_awid3_window_features(synthetic, "synthetic").iloc[0]
    assert window["frame_len_max"] == 3192
    assert window["frame_len_mean"] == 1646
    assert window["signal_dbm_mean"] == pytest.approx((-40 - 75 - 45) / 3)


def test_epoch_window_boundary_is_start_inclusive_and_end_exclusive():
    synthetic = pd.DataFrame({
        "Label": ["Normal", "Deauth"],
        "frame.time_epoch": [1.999, 2.0],
    })
    windows = extract_awid3_window_features(synthetic, "synthetic")
    assert windows["window_start_epoch"].tolist() == [1.0, 2.0]
    assert windows["window_label"].tolist() == ["Normal", "Deauth"]
