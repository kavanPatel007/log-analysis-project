"""
Test for parser correctness using the sample XML files in data/sample_logs.

This test ensures that:
- The parser returns a DataFrame
- Required columns are present
- At least one failed and one success event is parsed
"""

import pytest
import os
from scripts.parser import parse_directory

def test_parse_sample_logs():
    basedir = os.path.join(os.path.dirname(__file__), "..", "data", "sample_logs")
    df = parse_directory(basedir)
    assert not df.empty, "Parsed DataFrame should not be empty for sample logs"
    # required columns
    for col in ["timestamp", "event_id", "username", "ip", "status"]:
        assert col in df.columns
    # should contain 4625 and 4624 events based on sample files
    assert (df["event_id"] == 4625).any(), "Should have at least one failure event 4625"
    assert (df["event_id"] == 4624).any(), "Should have at least one success event 4624"