Windows Log Brute-Force Detection System

A complete, self-contained project that ingests Windows Event logs (XML/.evtx), detects brute-force attempts using rule-based logic and machine learning (IsolationForest), enriches events with offline GeoIP lookups, provides an interactive Plotly Dash dashboard, and can generate a PDF report.

This repository is intended as a blueprint and demo for a production detection pipeline. All components are runnable offline using the provided mock/sample data.



Why brute-force detection matters

Brute-force attacks are a common vector attackers use to gain unauthorized access to systems. Detecting them early reduces risk and helps security teams respond quickly. Automated detection with both rule-based heuristics and ML-based anomaly detection improves detection coverage and reduces false positives.
