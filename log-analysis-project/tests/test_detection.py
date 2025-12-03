"""
Test for brute-force detection logic.

This creates a small synthetic dataset to test whether the detect_bruteforce
function flags an IP that has >= 5 failures within 2 minutes.
"""

import pandas as pd
from datetime import datetime, timedelta, timezone
from scripts.detect_bruteforce import detect_bruteforce

def make_synthetic():
    base = datetime.now(timezone.utc)
    rows = []
    ip = "203.0.113.50"
    for i in range(6):
        rows.append({
            "timestamp": base + timedelta(seconds=20 * i),
            "event_id": 4625,
            "event_type": "failed_login",
            "username": f"user{i}",
            "ip": ip,
            "status": "Failure",
            "raw_event": ""
        })
    # add a success from another ip
    rows.append({
        "timestamp": base + timedelta(minutes=10),
        "event_id": 4624,
        "event_type": "successful_login",
        "username": "victim",
        "ip": "198.51.100.10",
        "status": "Success",
        "raw_event": ""
    })
    return pd.DataFrame(rows)

def test_detect_ip_bruteforce():
    df = make_synthetic()
    alerts = detect_bruteforce(df)
    # we expect at least one ip-type alert covering 203.0.113.50
    assert not alerts.empty, "Alerts should be detected"
    ips = alerts[alerts["flag_type"] == "ip"]["flag_value"].tolist()
    assert "203.0.113.50" in ips, "Synthetic IP with 6 rapid failures should be flagged"