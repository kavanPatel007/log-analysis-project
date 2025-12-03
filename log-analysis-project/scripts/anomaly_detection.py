"""
Machine Learning anomaly detection for failed-login frequency per IP.

- Uses IsolationForest to score frequency-based features per IP.
- Produces a per-IP table with anomaly_flag (True/False) and anomaly_score.
- Adds 'anomaly_flag' column to a copy of the failure events when requested.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from .extract_events import extract
from .utils import get_logger
from datetime import timedelta

logger = get_logger("anomaly_detection")


def compute_ip_failure_features(df, window=None):
    """
    Compute aggregated features per IP for failed logins.

    df: events DataFrame (must have timestamp, event_type, ip)
    window: optional timedelta to restrict to the latest window; if None, use all data
    Returns DataFrame indexed by ip with feature columns.
    """
    if df.empty:
        return pd.DataFrame(columns=["ip", "total_failures", "distinct_user_count", "failures_per_min"])

    fails = df[df["event_type"] == "failed_login"].copy()
    if window:
        latest = pd.to_datetime(fails["timestamp"]).max()
        cutoff = latest - window
        fails = fails[pd.to_datetime(fails["timestamp"]) >= cutoff]

    if fails.empty:
        return pd.DataFrame(columns=["ip", "total_failures", "distinct_user_count", "failures_per_min"])

    # Features:
    # - total_failures: count
    # - distinct_user_count: number of distinct target usernames tried
    # - failures_per_min: failures divided by duration in minutes (min 1)
    grouped = fails.groupby("ip")
    rows = []
    for ip, g in grouped:
        times = pd.to_datetime(g["timestamp"]).sort_values()
        duration_minutes = max(((times.max() - times.min()).total_seconds() / 60.0), 1.0)
        rows.append({
            "ip": ip,
            "total_failures": int(len(g)),
            "distinct_user_count": int(g["username"].nunique()),
            "failures_per_min": len(g) / duration_minutes,
        })
    return pd.DataFrame(rows).set_index("ip")


def run_isolation_forest(features_df, contamination=0.05, random_state=42):
    """
    Fit IsolationForest on features and produce anomaly labels/scores.

    Returns DataFrame with columns: anomaly_score, anomaly_flag
    """
    if features_df.empty:
        return pd.DataFrame(columns=["ip", "anomaly_score", "anomaly_flag"]).set_index("ip")

    # Use numeric features
    X = features_df.fillna(0).values
    model = IsolationForest(contamination=contamination, random_state=random_state)
    model.fit(X)
    scores = model.decision_function(X)
    preds = model.predict(X)  # -1 for anomaly, 1 for normal
    result = pd.DataFrame({
        "anomaly_score": scores,
        "anomaly_flag": (preds == -1)
    }, index=features_df.index)
    return result


def detect_anomalous_ips(df, window_minutes=60, contamination=0.05):
    """
    High-level helper:
    - compute features over the past `window_minutes`
    - run IsolationForest
    - merge features and anomaly outputs and return DataFrame
    """
    window = timedelta(minutes=window_minutes)
    features = compute_ip_failure_features(df, window=window)
    results = run_isolation_forest(features, contamination=contamination)
    merged = features.join(results)
    if not merged.empty:
        merged = merged.reset_index().rename(columns={"index": "ip"}).set_index("ip")
    return merged


if __name__ == "__main__":
    df = extract()
    anomalous = detect_anomalous_ips(df, window_minutes=120, contamination=0.1)
    print("Anomalous IPs:\n", anomalous[anomalous["anomaly_flag"]].to_string())