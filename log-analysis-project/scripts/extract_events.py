"""
Event extraction and mapping.

- Reads parsed events (or raw logs) and canonicalizes event types:
    4625 -> failed login (status Failure)
    4624 -> successful login (status Success)
- Produces events.csv with a lightweight schema used downstream.
"""

import pandas as pd
import os
from .parser import parse_directory
from .utils import get_logger

logger = get_logger("extract_events")


def map_event_types(df):
    """
    Add 'event_type' column mapping event_id to human-readable strings.
    """
    def map_type(row):
        if row["event_id"] == 4625:
            return "failed_login"
        if row["event_id"] == 4624:
            return "successful_login"
        return "other"
    df["event_type"] = df.apply(map_type, axis=1)
    return df


def extract(input_dir="data/sample_logs", output_csv="events_extracted.csv"):
    """
    Parse directory and write extracted events to CSV.
    """
    logger.info(f"Extracting events from {input_dir}")
    df = parse_directory(input_dir)
    if df.empty:
        logger.warning("No events to extract.")
        return df
    df = map_event_types(df)
    # Keep relevant columns
    out = df[["timestamp", "event_id", "event_type", "username", "ip", "status", "raw_event"]]
    out.to_csv(output_csv, index=False)
    logger.info(f"Wrote extracted events to {output_csv}")
    return out


if __name__ == "__main__":
    extract()