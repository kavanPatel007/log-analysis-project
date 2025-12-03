"""
Log parser module.

Responsibilities:
- Read XML-style event logs (and provide a fallback stub for .evtx using python-evtx if installed)
- Extract canonical fields: timestamp (UTC), event_id, username, ip, status
- Return a pandas DataFrame with normalized columns
"""

from xml.etree import ElementTree as ET
from datetime import datetime, timezone
import os
import glob
import pandas as pd
from .utils import xml_field, clean_timestamp, extract_ip_safe, get_logger

logger = get_logger("parser")

EXPECTED_FIELDS = ["timestamp", "event_id", "username", "ip", "status", "raw_event"]


def parse_event_element(event_elem):
    """
    Given an <Event> XML element (simplified schema), extract fields.
    Supports:
      - Event/System/EventID
      - Event/System/TimeCreated@SystemTime
      - Event/EventData/Data Name="TargetUserName" (or child TargetUserName)
      - Event/EventData/Data Name="IpAddress"
      - Any Data Name="Status" or assume based on EventID
    Returns dict with canonical keys.
    """
    # System block
    system = event_elem.find("System")
    event_id = None
    timestamp = None
    if system is not None:
        eid = system.find("EventID")
        if eid is not None and eid.text:
            try:
                event_id = int(eid.text.strip())
            except Exception:
                event_id = None
        timecreated = system.find("TimeCreated")
        if timecreated is not None:
            # TimeCreated may be an element with attribute SystemTime
            st = timecreated.attrib.get("SystemTime") or timecreated.text or ""
            timestamp = clean_timestamp(st)

    # EventData block (many Windows XML logs use <EventData><Data Name="...">value</Data></EventData>)
    eventdata = event_elem.find("EventData")
    username = ""
    ip = ""
    status = ""
    if eventdata is not None:
        # Try to find Data elements by Name attribute
        for data in eventdata.findall("Data"):
            name = data.attrib.get("Name") or ""
            text = (data.text or "").strip()
            if name.lower() in ("targetusername", "username", "accountname"):
                username = text
            elif name.lower() in ("ipaddress", "ip"):
                ip = extract_ip_safe(text)
            elif name.lower() in ("status", "result"):
                status = text
        # fallback: find child tags like <TargetUserName>
        if not username:
            username = xml_field(eventdata, "TargetUserName", "")
        if not ip:
            ip = xml_field(eventdata, "IpAddress", "")
            ip = extract_ip_safe(ip)
    # final normalize
    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "username": username or "",
        "ip": ip or "",
        "status": status or "",
        "raw_event": ET.tostring(event_elem, encoding="unicode"),
    }


def parse_xml_file(filepath):
    """
    Parse an XML logfile path into list of events (dicts).
    """
    logger.info(f"Parsing XML file: {filepath}")
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        events = []
        # Accept either <Events><Event>... or direct multiple Event children
        for ev in root.findall(".//Event"):
            events.append(parse_event_element(ev))
        return events
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML file {filepath}: {e}")
        return []


def parse_evtx_file(filepath):
    """
    Attempt to parse .evtx using python-evtx if installed.
    If the dependency is missing, this function returns an empty list.
    """
    try:
        from Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view
    except Exception as e:
        logger.warning("python-evtx not installed; skipping .evtx parsing fallback.")
        return []

    events = []
    try:
        with Evtx(filepath) as evtx:
            xml = evtx_file_xml_view(evtx)
            # xml is a single string containing many <Event> entries — parse as XML
            try:
                root = ET.fromstring("<Events>" + xml + "</Events>")
                for ev in root.findall(".//Event"):
                    events.append(parse_event_element(ev))
            except ET.ParseError:
                logger.exception("Failed to parse .evtx XML view. Skipping.")
    except Exception:
        logger.exception("Error when reading .evtx file.")
    return events


def parse_directory(dirpath):
    """
    Parse all .xml and .evtx files in a directory (non-recursive).
    Returns a pandas DataFrame with canonical columns and timestamp converted to UTC datetime.
    """
    files = glob.glob(os.path.join(dirpath, "*.xml")) + glob.glob(os.path.join(dirpath, "*.evtx"))
    all_events = []
    for f in files:
        if f.lower().endswith(".xml"):
            evs = parse_xml_file(f)
            all_events.extend(evs)
        elif f.lower().endswith(".evtx"):
            evs = parse_evtx_file(f)
            all_events.extend(evs)
    if not all_events:
        logger.info("No events found in directory.")
        return pd.DataFrame(columns=EXPECTED_FIELDS)
    # Build DataFrame
    df = pd.DataFrame(all_events)
    # Ensure timestamp column is datetime; some rows may be None
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    # Fill missing event_id with 0
    df["event_id"] = df["event_id"].fillna(0).astype(int)
    # normalize columns
    for c in ["username", "ip", "status"]:
        if c in df.columns:
            df[c] = df[c].fillna("")
    # add derived column: outcome based on event_id if status missing
    def derive_status(row):
        if row["status"]:
            return row["status"]
        if row["event_id"] == 4625:
            return "Failure"
        if row["event_id"] == 4624:
            return "Success"
        return "Unknown"
    df["status"] = df.apply(derive_status, axis=1)
    return df[EXPECTED_FIELDS]


if __name__ == "__main__":
    # Simple CLI for parsing a folder (for developers/testing)
    import argparse
    parser = argparse.ArgumentParser(description="Parse XML/.evtx logs into a normalized CSV.")
    parser.add_argument("input_dir", nargs="?", default="../data/sample_logs", help="Directory of logs")
    parser.add_argument("output_csv", nargs="?", default="parsed_events.csv", help="Output CSV file")
    args = parser.parse_args()
    df = parse_directory(args.input_dir)
    df.to_csv(args.output_csv, index=False)
    logger.info(f"Wrote parsed events to {args.output_csv}")