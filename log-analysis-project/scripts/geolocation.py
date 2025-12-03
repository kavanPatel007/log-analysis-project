"""
Offline/mock GeoIP lookup.

To keep the project runnable offline, we provide a small mock GeoIP mapping
embedded as JSON-like structures.

Function:
- geo_lookup(ip) -> dict with country, region, city, lat, lon

The mapping matches certain example IPs from sample logs.
"""

from ipaddress import ip_address, IPv4Address
from .utils import get_logger

logger = get_logger("geolocation")

# Mock IP to location mapping (CIDR-like prefixes supported via startswith for demo)
MOCK_GEO_DATA = [
    {
        "prefix": "203.0.113.",
        "country": "Exampleland",
        "region": "East Example",
        "city": "Exville",
        "lat": 34.05,
        "lon": -118.25
    },
    {
        "prefix": "198.51.100.",
        "country": "Testonia",
        "region": "North Test",
        "city": "Test City",
        "lat": 51.51,
        "lon": -0.13
    },
    {
        "prefix": "192.0.2.",
        "country": "Mockistan",
        "region": "Central Mock",
        "city": "Mock City",
        "lat": 35.68,
        "lon": 139.69
    }
]


def geo_lookup(ip):
    """
    Lookup IP in the mock table. Returns a dict.
    If not found or IP invalid, returns unknown placeholders.
    """
    result = {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0
    }
    if not ip:
        return result
    try:
        # Validate IP
        ip_address(ip)
    except Exception:
        logger.debug("Invalid IP passed to geo_lookup.")
        return result
    for rec in MOCK_GEO_DATA:
        if ip.startswith(rec["prefix"]):
            return {
                "country": rec["country"],
                "region": rec["region"],
                "city": rec["city"],
                "lat": rec["lat"],
                "lon": rec["lon"]
            }
    return result


if __name__ == "__main__":
    test_ips = ["203.0.113.10", "198.51.100.22", "192.0.2.5", "8.8.8.8"]
    for ip in test_ips:
        print(ip, geo_lookup(ip))