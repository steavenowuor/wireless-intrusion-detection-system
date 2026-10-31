"""Validation and time-window features for offline AWID3 CSV rows."""

from __future__ import annotations

import math
import json
import re

import numpy as np
import pandas as pd

LEAKAGE_TOKENS = ("label", "target", "class", "attack_type", "attack_category",
                  "attack_name", "attack_flag", "attack_step")
IDENTIFIER_NAMES = {"id", "mac", "mac_address", "bssid", "station_mac", "device_id",
                    "capture_id", "session_id"}
PROVENANCE_NAMES = {"source_file", "source_files", "source_labels", "source_label_counts"}
TIME_NAMES = {"frame.number", "frame.time", "frame.time_epoch", "frame.time_relative",
              "frame.time_delta", "frame.time_delta_displayed", "window_start_epoch"}
ADDRESS_NAMES = {"wlan.sa", "wlan.ta", "wlan.da", "wlan.ra", "wlan.bssid"}
SIGNED_INT8_MIN = -128
SIGNED_INT8_MAX = 127
UINT32_MAX = 2**32 - 1


def validate_feature_frame(features: pd.DataFrame) -> pd.DataFrame:
    """Return a safe copy of tabular features after simple validation."""
    if not isinstance(features, pd.DataFrame):
        raise TypeError("Features must be provided as a pandas DataFrame")
    if features.empty or features.shape[1] == 0:
        raise ValueError("At least one feature row and column are required")
    if features.columns.duplicated().any():
        raise ValueError("Feature column names must be unique")
    for name in features.columns:
        normalized = str(name).strip().lower().replace("-", "_").replace(" ", "_")
        if any(token in normalized for token in LEAKAGE_TOKENS):
            raise ValueError(f"target/label-like column '{name}' was passed as a feature")
    return features.copy()


def remove_obvious_leakage(features: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Drop target, group, packet-address, and raw chronology columns."""
    if not isinstance(features, pd.DataFrame):
        raise TypeError("Features must be provided as a pandas DataFrame")
    if features.columns.duplicated().any():
        raise ValueError("Feature column names must be unique")
    known_metadata = [name for name in features.columns
                      if str(name).strip().lower().replace("-", "_").replace(" ", "_")
                      in PROVENANCE_NAMES]
    safe = validate_feature_frame(features.drop(columns=known_metadata))
    dropped = list(known_metadata)
    for name in safe.columns:
        normalized = str(name).strip().lower().replace("-", "_").replace(" ", "_")
        if (normalized in IDENTIFIER_NAMES or normalized in PROVENANCE_NAMES or normalized in TIME_NAMES or
                normalized in ADDRESS_NAMES or normalized.endswith("_id")):
            dropped.append(name)
    dropped = list(dict.fromkeys(dropped))
    safe = safe.drop(columns=[name for name in dropped if name in safe.columns])
    if safe.shape[1] == 0:
        raise ValueError("No usable feature columns remain after excluding identifiers")
    return safe, dropped


def parse_numeric_field(values: pd.Series) -> pd.Series:
    """Parse decimal, hexadecimal, and boolean-like tshark fields safely."""
    def parse_one(value):
        if pd.isna(value):
            return np.nan
        if isinstance(value, (bool, np.bool_)):
            return int(value)
        text = str(value).strip()
        if not text:
            return np.nan
        if text.lower() in {"true", "false"}:
            return int(text.lower() == "true")
        try:
            if re.fullmatch(r"[-+]?0x[0-9a-f]+", text, flags=re.IGNORECASE):
                return int(text, 16)
            result = float(text)
            return result if math.isfinite(result) else np.nan
        except (TypeError, ValueError, OverflowError):
            return np.nan

    return values.map(parse_one).astype("float64")


def parse_frame_length_field(values: pd.Series) -> pd.Series:
    """Parse tshark frame.len as an unsigned 32-bit integral byte count.

    Do not impose the 802.11 MPDU length as a cap: tshark's frame.len is a
    frame-level length field and the AWID3 export may include aggregated data.
    """
    numeric = parse_numeric_field(values)
    valid = numeric.between(0, UINT32_MAX) & numeric.mod(1).eq(0)
    return numeric.where(valid)


def parse_dbm_signal_fields(wlan_radio_values: pd.Series | None,
                            radiotap_values: pd.Series | None,
                            index: pd.Index) -> pd.Series:
    """Prefer wlan_radio dBm, then use representable radiotap dBm as fallback.

    Both Wireshark fields are signed 8-bit values. Values outside that field
    range are treated as invalid measurements, not as numeric signal levels.
    This is a representation check, not a claim about undocumented sentinels.
    """
    def valid_dbm(values):
        if values is None:
            return pd.Series(np.nan, index=index, dtype="float64")
        parsed = parse_numeric_field(values)
        return parsed.where(parsed.between(SIGNED_INT8_MIN, SIGNED_INT8_MAX))

    preferred = valid_dbm(wlan_radio_values)
    fallback = valid_dbm(radiotap_values)
    return preferred.fillna(fallback)


def extract_awid3_window_features(rows: pd.DataFrame, capture_id: str,
                                  window_seconds: float = 1.0) -> pd.DataFrame:
    """Aggregate packet rows into fixed UTC-epoch windows.

    ``source_labels`` and ``source_label_counts`` preserve original row-label
    evidence. ``window_label`` is an aggregate target: any non-Normal row makes
    the window malicious, with Deauth retained when present. A Deauth-labelled
    window does not independently prove a flood episode.
    """
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be a finite positive number")
    required = {"Label", "frame.time_epoch"}
    missing = required - set(rows.columns)
    if missing:
        raise ValueError("Missing required AWID3 columns: " + ", ".join(sorted(missing)))
    if not capture_id or not str(capture_id).strip():
        raise ValueError("capture_id must be explicitly supplied")
    if rows.empty:
        return pd.DataFrame()

    data = rows.copy()
    epoch = parse_numeric_field(data["frame.time_epoch"])
    valid_time = epoch.notna() & epoch.ge(0)
    data = data.loc[valid_time].copy()
    if data.empty:
        return pd.DataFrame()
    data["_epoch"] = epoch.loc[valid_time]
    data["_window"] = np.floor(data["_epoch"] / window_seconds).astype("int64")
    labels = data["Label"].astype("string").str.strip()
    if labels.isna().any() or labels.eq("").any():
        raise ValueError("AWID3 Label has missing or empty values in valid-timestamp rows")
    data["_label"] = labels

    optional = {
        "wlan.fc.type": "_fc_type", "wlan.fc.subtype": "_fc_subtype",
        "wlan.fc.retry": "_retry", "frame.len": "_frame_len",
        "radiotap.dbm_antsignal": "_signal", "wlan_radio.signal_dbm": "_signal_alt",
        "wlan.fixed.reason_code": "_reason", "wlan.ta": "_transmitter",
        "wlan.sa": "_source",
    }
    for column, internal in optional.items():
        if column in data.columns:
            data[internal] = data[column]
    for internal in ("_fc_type", "_fc_subtype", "_retry", "_reason"):
        if internal in data:
            data[internal] = parse_numeric_field(data[internal])
    data["_frame_len"] = parse_frame_length_field(
        data["frame.len"] if "frame.len" in data else pd.Series(np.nan, index=data.index)
    )
    data["_signal"] = parse_dbm_signal_fields(
        data["wlan_radio.signal_dbm"] if "wlan_radio.signal_dbm" in data else None,
        data["radiotap.dbm_antsignal"] if "radiotap.dbm_antsignal" in data else None,
        data.index,
    )
    data["_is_mgmt"] = data.get("_fc_type", pd.Series(np.nan, index=data.index)).eq(0)
    data["_is_deauth_frame"] = data["_is_mgmt"] & data.get(
        "_fc_subtype", pd.Series(np.nan, index=data.index)).eq(12)
    data["_is_retry"] = data.get("_retry", pd.Series(np.nan, index=data.index)).eq(1)
    transmitter = data.get("_transmitter", data.get("_source", pd.Series(index=data.index, dtype="object")))
    data["_transmitter"] = transmitter

    normal_values = {"normal", "benign", "0"}
    output = []
    for window, group in data.groupby("_window", sort=True):
        source_labels = {value for value in group["_label"].astype(str)}
        label_counts = group["_label"].astype(str).value_counts().sort_index().to_dict()
        attack_labels = {value for value in source_labels if value.strip().lower() not in normal_values}
        deauth_labels = {value for value in attack_labels
                         if "deauth" in value.lower().replace("_", "").replace("-", "")}
        label = sorted(deauth_labels or attack_labels)[0] if attack_labels else "Normal"
        duration = min(window_seconds, max(0.0, (window + 1) * window_seconds - window * window_seconds))
        frame_lengths = group.get("_frame_len", pd.Series(dtype="float64")).dropna()
        signals = group.get("_signal", pd.Series(dtype="float64")).dropna()
        reasons = group.get("_reason", pd.Series(dtype="float64")).dropna()
        source_epochs = group["_epoch"]
        source_frame_numbers = (parse_numeric_field(group["frame.number"])
                                if "frame.number" in group else pd.Series(dtype="float64"))
        source_files_in_order = list(dict.fromkeys(
            group.get("_source_file", pd.Series(dtype="string")).dropna().astype(str)
        ))
        backward_steps = group.get("_timestamp_backward_seconds", pd.Series(0.0, index=group.index))
        packet_count = len(group)
        deauth_count = int(group["_is_deauth_frame"].sum())
        output.append({
            "capture_id": str(capture_id),
            "source_files": "|".join(source_files_in_order),
            "window_start_epoch": float(window * window_seconds),
            "window_seconds": float(window_seconds),
            # Keep observed epoch values for traceability. The original source
            # rows remain authoritative; these are exact window summaries.
            "source_time_epoch_first": float(source_epochs.iloc[0]),
            "source_time_epoch_last": float(source_epochs.iloc[-1]),
            "source_time_epoch_min": float(source_epochs.min()),
            "source_time_epoch_max": float(source_epochs.max()),
            "timestamp_backward_movement_count": int(backward_steps.gt(0).sum()),
            "timestamp_backward_max_seconds": float(backward_steps.max()),
            "source_frame_number_first": (float(source_frame_numbers.iloc[0])
                                          if len(source_frame_numbers) else np.nan),
            "source_frame_number_last": (float(source_frame_numbers.iloc[-1])
                                         if len(source_frame_numbers) else np.nan),
            "packet_count": packet_count,
            "management_frame_count": int(group["_is_mgmt"].sum()),
            "deauth_frame_count": deauth_count,
            "deauth_frames_per_second": deauth_count / duration if duration else 0.0,
            "deauth_frame_fraction": deauth_count / packet_count if packet_count else 0.0,
            "retry_frame_count": int(group["_is_retry"].sum()),
            "retry_frame_fraction": float(group["_is_retry"].sum()) / packet_count if packet_count else 0.0,
            "frame_len_mean": float(frame_lengths.mean()) if len(frame_lengths) else np.nan,
            "frame_len_max": float(frame_lengths.max()) if len(frame_lengths) else np.nan,
            "signal_dbm_mean": float(signals.mean()) if len(signals) else np.nan,
            "signal_dbm_min": float(signals.min()) if len(signals) else np.nan,
            "reason_code_count": int(len(reasons)),
            "unique_transmitter_count": int(group["_transmitter"].dropna().astype(str).nunique()),
            "window_label": label,
            "source_labels": "|".join(sorted(source_labels)),
            "source_label_counts": json.dumps(label_counts, sort_keys=True),
            "mixed_window": len(source_labels) > 1,
        })
    return pd.DataFrame(output)
