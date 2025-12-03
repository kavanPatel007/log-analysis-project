Windows Log Brute-Force Detection System

A complete, self-contained project that ingests Windows Event logs (XML/.evtx), detects brute-force attempts using rule-based logic and machine learning (IsolationForest), enriches events with offline GeoIP lookups, provides an interactive Plotly Dash dashboard, and can generate a PDF report.

This repository is intended as a blueprint and demo for a production detection pipeline. All components are runnable offline using the provided mock/sample data.



Why brute-force detection matters

Brute-force attacks are a common vector attackers use to gain unauthorized access to systems. Detecting them early reduces risk and helps security teams respond quickly. Automated detection with both rule-based heuristics and ML-based anomaly detection improves detection coverage and reduces false positives.


 Architecture (ASCII diagram)

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

