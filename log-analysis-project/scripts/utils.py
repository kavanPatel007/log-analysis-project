"""
Utility module for log parsing and helper functions.

Contains:
- xml_field: safe XML field extractor
- clean_timestamp: parse and normalize timestamps (UTC-aware)
- extract_ip_safe: validate and sanitize IP addresses
- get_logger: simple logging wrapper
"""

import re
import logging
from datetime import datetime, timezone
from ipaddress import ip_address, AddressValueError

ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S",
]


def xml_field(elem, tagname, default=""):
    """
    Safely extract text from an XML element's child tag.
    - elem: XML element (from ElementTree)
    - tagname: name of the child tag
    - default: value to return if not found
    """
    if elem is None:
        return default
    child = elem.find(tagname)
    if child is None:
        return default
    return child.text or default


def clean_timestamp(timestr):
    """
    Normalize a timestamp string into a timezone-aware UTC datetime object.
    Tries multiple known formats. Returns None on failure.
    """
    if not timestr:
        return None
    # If it is an attribute string like '2025-11-30T12:00:01Z', return parsed
    for fmt in ISO_FORMATS:
        try:
            dt = datetime.strptime(timestr, fmt)
            # treat as UTC if trailing Z or no timezone info
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
    # As fallback, try dateutil if available
    try:
        from dateutil import parser as date_parser
        dt = date_parser.parse(timestr)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})$"
)


def extract_ip_safe(ip_str):
    """
    Validate an IP string and return normalized string or empty string.
    Works for IPv4 primarily for the demo. Uses ipaddress module for correctness.
    """
    if not ip_str:
        return ""
    ip_str = ip_str.strip()
    # Some windows events may include '::1' or '-' placeholders
    if ip_str in ("-", "127.0.0.1", "::1"):
        return ""
    try:
        # Will raise on invalid input
        ip_addr = ip_address(ip_str)
        # Normalize IPv4-mapped IPv6 if present
        return ip_addr.exploded
    except AddressValueError:
        # Try regex fallback
        if IPV4_RE.match(ip_str):
            return ip_str
        return ""


def get_logger(name="log_analysis"):
    """
    Returns a configured logger for the project with INFO level and a simple format.
    Use this to standardize logs in scripts.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        fmt = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger