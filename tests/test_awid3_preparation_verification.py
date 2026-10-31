"""Verification utility tests use small synthetic prepared data only."""

import pandas as pd
import pytest

from src.data_preparation import prepare_awid3_subset
from src.verify_awid3_preparation import verify_prepared_awid3


def test_synthetic_prepared_manifest_and_window_counts_verify(tmp_path):
    source = tmp_path / "source.csv"
    pd.DataFrame({
        "Label": ["Normal", "Deauth"],
        "frame.number": [1, 2],
        "frame.time_epoch": [10.1, 11.1],
    }).to_csv(source, index=False)
    output = tmp_path / "windows.csv"
    prepare_awid3_subset(
        [source], output, "synthetic-sequence", chunksize=1,
        frame_ordered_sequence=True,
    )

    summary = verify_prepared_awid3(
        output, expected_files=1, expected_rows=2, expected_windows=2,
        expected_normal_windows=1, expected_deauth_windows=1,
        expected_mixed_windows=0,
    )
    assert summary["status"] == "verified_counts_and_window_bounds"
    assert summary["source_rows"] == 2


def test_synthetic_verifier_fails_on_wrong_expected_distribution(tmp_path):
    source = tmp_path / "source.csv"
    pd.DataFrame({
        "Label": ["Normal", "Deauth"],
        "frame.number": [1, 2],
        "frame.time_epoch": [10.1, 11.1],
    }).to_csv(source, index=False)
    output = tmp_path / "windows.csv"
    prepare_awid3_subset(
        [source], output, "synthetic-sequence", chunksize=1,
        frame_ordered_sequence=True,
    )

    with pytest.raises(ValueError, match="window label distribution"):
        verify_prepared_awid3(
            output, expected_files=1, expected_rows=2, expected_windows=2,
            expected_normal_windows=0, expected_deauth_windows=2,
            expected_mixed_windows=0,
        )
