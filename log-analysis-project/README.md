# Windows Log Brute-Force Detection System

A complete, self-contained project that ingests Windows Event logs (XML/.evtx), detects brute-force attempts using rule-based logic and machine learning (IsolationForest), enriches events with offline GeoIP lookups, provides an interactive Plotly Dash dashboard, and can generate a PDF report.

This repository is intended as a blueprint and demo for a production detection pipeline. All components are runnable offline using the provided mock/sample data.

---

## Why brute-force detection matters

Brute-force attacks are a common vector attackers use to gain unauthorized access to systems. Detecting them early reduces risk and helps security teams respond quickly. Automated detection with both rule-based heuristics and ML-based anomaly detection improves detection coverage and reduces false positives.

---

## Architecture (ASCII diagram)

log-analysis-project/
├── data/                    # sample logs
├── scripts/                 # parsing, detection, ML, geolocation, report
├── dashboard/               # Dash UI
├── tests/                   # unit tests
└── reports/                 # generated reports (not committed)

Flow:
1. Input logs (.xml / .evtx) -> parser.py
2. Extract events -> extract_events.py -> events_extracted.csv
3. Rule-based detection -> detect_bruteforce.py -> bruteforce_alerts.csv
4. ML anomaly detection -> anomaly_detection.py
5. GeoIP enrichment (mock) -> geolocation.py
6. Dashboard -> dashboard/app.py (visualize)
7. PDF report -> generate_report.py

---

## Quickstart / Installation

1. Create and activate a virtualenv (recommended)
   - python -m venv .venv
   - source .venv/bin/activate  (Windows: .venv\Scripts\activate)

2. Install requirements:
   - pip install -r requirements.txt

Note: `python-evtx` is optional. The parser supports XML-style exported logs. If you want to parse `.evtx` directly, install `python-evtx`.

---

## How to run the pipeline

All commands assume you are at the project root.

1. Parse sample logs and produce extracted events:

    python -m scripts.extract_events

This will read `data/sample_logs/` and write `events_extracted.csv`.

2. Run brute-force detection:

    python -m scripts.detect_bruteforce

This will read `events_extracted.csv` (or re-run extraction) and write `bruteforce_alerts.csv`.

3. Run ML anomaly detection (IsolationForest):

    python -m scripts.anomaly_detection

This prints anomalous IPs based on recent failed login patterns.

4. Generate PDF report:

    python -m scripts.generate_report

This will produce `bruteforce_report.pdf` and image assets under `reports_assets/`.

---

## Dashboard

Run the Dash app locally:

    python -m dashboard.app

Open http://127.0.0.1:8050 in your browser. Features:

- KPIs showing total events, failed logins, unique IPs, alerts
- Histogram of failed logins by IP
- Time-series of failed logins
- World map scatter using mock GeoIP
- Interactive alerts table
- Buttons to refresh data and generate PDF report

---

## Tests

Run tests with pytest:

    pytest -q

There are two simple tests:
- test_parser.py: validates parser extracts expected fields from sample XML logs.
- test_detection.py: tests the brute-force detection logic on synthetic data.

---

## File overview

- data/sample_logs/ : Sample XML logs (fake1.xml, fake2.xml)
- scripts/
  - parser.py : XML and .evtx parsing, normalization
  - extract_events.py : Extract event types and write events_extracted.csv
  - detect_bruteforce.py : Rule-based brute-force detection and alerts CSV
  - anomaly_detection.py : IsolationForest-based anomaly detection per IP
  - geolocation.py : Offline/mock geolocation lookup
  - generate_report.py : Create charts and render PDF with reportlab
  - utils.py : Helper utilities and logging wrapper
- dashboard/
  - app.py : Dash application
  - components.py : UI building blocks for dashboard
- tests/ : pytest unit tests
- requirements.txt : Python dependencies

---

## Screenshots (placeholders)

- Dashboard KPIs
  [screenshot-placeholder-dashboard-kpis.png]

- Histogram of failed logins
  [screenshot-placeholder-histogram.png]

- PDF report first page
  [screenshot-placeholder-report.png]

---

## Future improvements

- Replace mock GeoIP with a local MaxMind DB reader (e.g., geoip2 with offline DB)
- Add streaming ingestion from SIEM or Windows Event Forwarding (WEF)
- Improve ML features (behavioral sequences, time-of-day patterns)
- Add feedback loop to label false positives and retrain models
- Integrate alerting (email/SOAR) for high-confidence detections
- Harden parsing for different Windows Event XML schema variants
- Add role-based access and auth to the dashboard

---

## License & Attribution

This project is a demonstration. Incorporate with care in production environments and adapt to your organization's logging schema, privacy rules, and operational practices.