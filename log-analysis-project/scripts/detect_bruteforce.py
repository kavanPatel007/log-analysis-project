"""
Brute-force detection module implementing rule-based detection.

Rules implemented:
- Same IP: if >= 5 failures within a sliding 2-minute window => flag IP
- Same username: if >= 5 failures within a sliding 10-minute window => flag username

Outputs:
- A function returning flagged IPs and usernames
- Save bruteforce_alerts.csv with details
"""

import pandas as pd
from datetime import timedelta
import os
from .extract_events import extract
from .utils import get_logger

logger = get_logger("detect_bruteforce")


def detect_bruteforce(df, ip_threshold=5, ip_window=timedelta(minutes=2),
                      user_threshold=5, user_window=timedelta(minutes=10)):
    """
    Detect brute-force attempts, returning a DataFrame of alerts.

    df: DataFrame containing parsed/extracted events (must have timestamp, event_type, username, ip)
    ip_threshold, ip_window: threshold and timeframe for IP-based detection
    user_threshold, user_window: threshold and timeframe for username-based detection
    """
    if df.empty:
        return pd.DataFrame(columns=[
            "flag_type", "flag_value", "first_seen", "last_seen", "count", "sample_ips", "sample_users"
        ])

    # Work only with failures
    fails = df[df["event_type"] == "failed_login"].copy()
    fails = fails.sort_values("timestamp")
    alerts = []

    # IP-based sliding window
    # For efficiency, group by IP and scan timestamps
    for ip, group in fails.groupby("ip"):
        if not ip:
            continue
        times = pd.to_datetime(group["timestamp"]).sort_values()
        # sliding window: count number of events inside window for each event as start
        # simpler: use pandas rolling via integer positions
        # We'll use two-pointer method for clarity
        start_idx = 0
        times_list = list(times)
        for i, t in enumerate(times_list):
            # move start forward while window exceeded
            while start_idx < i and (t - times_list[start_idx]) > ip_window:
                start_idx += 1
            count = i - start_idx + 1
            if count >= ip_threshold:
                first_seen = times_list[start_idx]
                last_seen = t
                sample_users = group[(group["timestamp"] >= first_seen) & (group["timestamp"] <= last_seen)]["username"].unique().tolist()
                alerts.append({
                    "flag_type": "ip",
                    "flag_value": ip,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "count": count,
                    "sample_ips": [ip],
                    "sample_users": sample_users,
                })
                # advance start to avoid duplicate overlapping alerts
                start_idx = i + 1

    # Username-based detection
    for user, group in fails.groupby("username"):
        if not user:
            continue
        times = pd.to_datetime(group["timestamp"]).sort_values()
        start_idx = 0
        times_list = list(times)
        for i, t in enumerate(times_list):
            while start_idx < i and (t - times_list[start_idx]) > user_window:
                start_idx += 1
            count = i - start_idx + 1
            if count >= user_threshold:
                first_seen = times_list[start_idx]
                last_seen = t
                sample_ips = group[(group["timestamp"] >= first_seen) & (group["timestamp"] <= last_seen)]["ip"].unique().tolist()
                alerts.append({
                    "flag_type": "username",
                    "flag_value": user,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "count": count,
                    "sample_ips": sample_ips,
                    "sample_users": [user],
                })
                start_idx = i + 1

    alerts_df = pd.DataFrame(alerts)
    if not alerts_df.empty:
        # Normalize timestamps and save CSV
        alerts_df["first_seen"] = pd.to_datetime(alerts_df["first_seen"])
        alerts_df["last_seen"] = pd.to_datetime(alerts_df["last_seen"])
        outpath = "bruteforce_alerts.csv"
        alerts_df.to_csv(outpath, index=False)
        logger.info(f"Saved brute-force alerts to {outpath}")
    else:
        logger.info("No brute-force alerts detected.")
        alerts_df = alerts_df[["flag_type", "flag_value", "first_seen", "last_seen", "count", "sample_ips", "sample_users"]]

    return alerts_df


if __name__ == "__main__":
    # Run end-to-end detection using sample data
    df = extract()
    alerts = detect_bruteforce(df)
    print(alerts.to_string(index=False))